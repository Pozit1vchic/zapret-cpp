#include "zc/rules.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <sstream>
#include <system_error>
#include <utility>

#include "zc/tls.hpp"

namespace zc {
namespace {

constexpr int kMaxIncludeDepth = 8;

std::string trim(std::string_view s) {
    std::size_t first = 0;
    while (first < s.size() && std::isspace(static_cast<unsigned char>(s[first])) != 0) ++first;
    std::size_t last = s.size();
    while (last > first && std::isspace(static_cast<unsigned char>(s[last - 1])) != 0) --last;
    return std::string(s.substr(first, last - first));
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool parse_bool(std::string_view s, bool& out) noexcept {
    const std::string v = lower(std::string(s));
    if (v == "1" || v == "true" || v == "yes" || v == "on") { out = true; return true; }
    if (v == "0" || v == "false" || v == "no" || v == "off") { out = false; return true; }
    return false;
}

bool parse_int(std::string_view s, int lo, int hi, int& out) noexcept {
    if (s.empty()) return false;
    int value = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
    if (ec != std::errc{} || ptr != s.data() + s.size()) return false;
    if (value < lo || value > hi) return false;
    out = value;
    return true;
}

void add_problem(std::vector<ConfigProblem>& problems, const std::filesystem::path& file,
                 std::size_t line, std::string message) {
    if (problems.size() < 64) problems.push_back(ConfigProblem{file, line, std::move(message)});
}

// Accepts "0.0.0.0 example.com", "||ads.example^", "*.example.com", "=example.com",
// ".example.com", "example.com". `subdomains_only` reports the "*.x" / ".x" decoration,
// which means "subdomains but not the bare domain".
std::optional<std::string> clean_domain_token(std::string_view token,
                                              bool* subdomains_only = nullptr) {
    token = trim(token);
    if (subdomains_only != nullptr) *subdomains_only = false;
    if (token.empty()) return std::nullopt;
    const std::size_t space = token.find_first_of(" \t");
    if (space != std::string_view::npos) token = trim(token.substr(space + 1));
    while (!token.empty() && (token.front() == '|' || token.front() == '^' || token.front() == '=')) {
        token.remove_prefix(1);
    }
    while (!token.empty() && token.back() == '^') token.remove_suffix(1);
    if (!token.empty() && (token.front() == '*' || token.front() == '.')) {
        if (subdomains_only != nullptr) *subdomains_only = true;
        while (!token.empty() && (token.front() == '*' || token.front() == '.')) {
            token.remove_prefix(1);
        }
    }
    while (!token.empty() && token.back() == '.') token.remove_suffix(1);
    return normalize_hostname(token);
}

// ASCII case-insensitive comparison without allocating. Hostnames are ASCII, and the
// hot path must not allocate for every candidate rule.
bool iequals_ascii(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        unsigned char left = static_cast<unsigned char>(a[i]);
        unsigned char right = static_cast<unsigned char>(b[i]);
        if (left >= 'A' && left <= 'Z') left = static_cast<unsigned char>(left - 'A' + 'a');
        if (right >= 'A' && right <= 'Z') right = static_cast<unsigned char>(right - 'A' + 'a');
        if (left != right) return false;
    }
    return true;
}

// Suffix test with a mandatory label boundary: "notexample.com" must not match
// "example.com".
bool host_matches_suffix(std::string_view host, std::string_view suffix,
                         bool subdomains_only) noexcept {
    if (host.size() < suffix.size()) return false;
    if (host.size() == suffix.size()) {
        return !subdomains_only && iequals_ascii(host, suffix);
    }
    if (host[host.size() - suffix.size() - 1] != '.') return false;
    return iequals_ascii(host.substr(host.size() - suffix.size()), suffix);
}

std::vector<std::string> split_labels(const std::string& host) {
    std::vector<std::string> labels;
    labels.reserve(6);
    std::size_t start = 0;
    for (;;) {
        const std::size_t dot = host.find('.', start);
        if (dot == std::string::npos) {
            labels.push_back(host.substr(start));
            break;
        }
        labels.push_back(host.substr(start, dot - start));
        start = dot + 1;
    }
    return labels;
}

}  // namespace

// ---------------------------------------------------------------------------
// Strategy names
// ---------------------------------------------------------------------------

const char* strategy_name(Strategy s) noexcept {
    switch (s) {
    case Strategy::pass: return "pass";
    case Strategy::split: return "split";
    case Strategy::disorder: return "disorder";
    case Strategy::multisplit: return "multisplit";
    case Strategy::multidisorder: return "multidisorder";
    case Strategy::fake: return "fake";
    case Strategy::fake_split: return "fake-split";
    case Strategy::fake_disorder: return "fake-disorder";
    case Strategy::fake_multidisorder: return "fake-multidisorder";
    case Strategy::fake_auto: return "fake-auto";
    case Strategy::quic_fake: return "quic-fake";
    }
    return "?";
}

bool parse_strategy(std::string_view name, Strategy& out) noexcept {
    struct Entry { std::string_view name; Strategy value; };
    static constexpr Entry kTable[] = {
        {"pass", Strategy::pass},
        {"split", Strategy::split},
        {"disorder", Strategy::disorder},
        {"multisplit", Strategy::multisplit},
        {"multidisorder", Strategy::multidisorder},
        {"fake", Strategy::fake},
        {"fake-split", Strategy::fake_split},
        {"fake,multisplit", Strategy::fake_split},
        {"fake-disorder", Strategy::fake_disorder},
        {"fake-multidisorder", Strategy::fake_multidisorder},
        {"fake-auto", Strategy::fake_auto},
        {"quic-fake", Strategy::quic_fake},
    };
    const std::string lowered = lower(std::string(name));
    for (const Entry& e : kTable) {
        if (lowered == e.name) {
            out = e.value;
            return true;
        }
    }
    return false;
}

bool strategy_uses_fake(Strategy s) noexcept {
    switch (s) {
    case Strategy::fake:
    case Strategy::fake_split:
    case Strategy::fake_disorder:
    case Strategy::fake_multidisorder:
    case Strategy::fake_auto:
    case Strategy::quic_fake:
        return true;
    default:
        return false;
    }
}

bool strategy_splits(Strategy s) noexcept {
    switch (s) {
    case Strategy::split:
    case Strategy::disorder:
    case Strategy::multisplit:
    case Strategy::multidisorder:
    case Strategy::fake_split:
    case Strategy::fake_disorder:
    case Strategy::fake_multidisorder:
    case Strategy::fake_auto:
        return true;
    default:
        return false;
    }
}

// ---------------------------------------------------------------------------
// diagnostics and helpers
// ---------------------------------------------------------------------------

std::string ConfigProblem::to_string() const {
    std::string out = file.string();
    if (line != 0) out += ":" + std::to_string(line);
    out += ": " + message;
    return out;
}

std::optional<std::string> normalize_domain(std::string_view raw) noexcept {
    return clean_domain_token(raw);
}

bool Rule::requires_host() const noexcept {
    for (const Matcher& m : matchers) {
        if (m.kind == MatcherKind::host_exact || m.kind == MatcherKind::host_suffix) return true;
    }
    return false;
}

std::size_t Rule::host_suffix_length() const noexcept {
    for (const Matcher& m : matchers) {
        if (m.kind == MatcherKind::host_exact || m.kind == MatcherKind::host_suffix) {
            return m.text.size();
        }
    }
    return 0;
}

// Full conjunction: every matcher on the rule must hold.
bool Rule::satisfies(std::string_view host, const IpAddress& destination,
                     std::uint16_t destination_port, std::uint8_t protocol) const noexcept {
    for (const Matcher& m : matchers) {
        switch (m.kind) {
        case MatcherKind::host_exact:
            if (host.empty() || !iequals_ascii(host, m.text)) return false;
            break;
        case MatcherKind::host_suffix:
            if (host.empty() || !host_matches_suffix(host, m.text, m.subdomains_only)) {
                return false;
            }
            break;
        case MatcherKind::address:
            if (!(destination == m.address)) return false;
            break;
        case MatcherKind::cidr:
            if (!m.network.contains(destination)) return false;
            break;
        case MatcherKind::port:
            if (destination_port != m.port) return false;
            break;
        case MatcherKind::protocol:
            if (protocol != m.protocol) return false;
            break;
        case MatcherKind::none:
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// loading
// ---------------------------------------------------------------------------

bool RuleSet::load_text(std::string_view text, const std::filesystem::path& origin,
                        std::vector<ConfigProblem>& problems, int include_depth) {
    if (include_depth > kMaxIncludeDepth) {
        add_problem(problems, origin, 0, "include nesting too deep");
        return false;
    }

    bool ok = true;
    std::size_t line_number = 0;
    std::size_t pos = 0;
    while (true) {
        const std::size_t newline = text.find('\n', pos);
        const std::size_t end = newline == std::string_view::npos ? text.size() : newline;
        std::string line(text.substr(pos, end - pos));
        pos = end + 1;
        ++line_number;

        const std::size_t comment = line.find_first_of("#;");
        if (comment != std::string::npos) line.resize(comment);
        line = trim(line);
        if (!line.empty()) {
            std::istringstream stream(line);
            std::string first;
            stream >> first;

            if (first == "include" || first == ".include") {
                std::string pattern;
                stream >> pattern;
                if (pattern.empty()) {
                    add_problem(problems, origin, line_number, "include needs a path");
                    ok = false;
                } else {
                    const std::filesystem::path base = origin.has_parent_path()
                                                          ? origin.parent_path()
                                                          : std::filesystem::path(".");
                    const std::filesystem::path target = base / pattern;
                    std::error_code ec;
                    if (!std::filesystem::is_regular_file(target, ec)) {
                        add_problem(problems, origin, line_number,
                                    "include not found: " + pattern);
                        ok = false;
                    } else {
                        ++include_count_;
                        if (!load_file(target, problems, include_depth + 1)) ok = false;
                    }
                }
            } else {
                ok = parse_rule_line(line, origin, line_number, problems) && ok;
            }
        }

        if (newline == std::string_view::npos) break;
    }
    compile();
    return ok;
}

bool RuleSet::parse_rule_line(const std::string& line, const std::filesystem::path& origin,
                              std::size_t line_number, std::vector<ConfigProblem>& problems) {
    Rule rule;
    rule.order = rules_.size();

    std::istringstream stream(line);
    std::string token;
    bool have_action = false;

    while (stream >> token) {
        const std::size_t eq = token.find('=');
        const std::size_t colon = token.find(':');

        // ---- prefix matchers (ip:, cidr:, port:, proto:) ----
        if (eq == std::string::npos && colon != std::string::npos) {
            const std::string key = lower(token.substr(0, colon));
            const std::string value = token.substr(colon + 1);
            Matcher m;
            if (key == "ip") {
                m.kind = MatcherKind::address;
                m.address = IpAddress::parse(value);
                if (m.address.family == IpFamily::none) {
                    add_problem(problems, origin, line_number, "invalid address: " + value);
                    return false;
                }
                rule.matchers.push_back(std::move(m));
                continue;
            }
            if (key == "cidr") {
                m.kind = MatcherKind::cidr;
                const auto net = IpNetwork::parse(value);
                if (!net) {
                    add_problem(problems, origin, line_number, "invalid CIDR: " + value);
                    return false;
                }
                m.network = *net;
                rule.matchers.push_back(std::move(m));
                continue;
            }
            if (key == "port") {
                int number = 0;
                if (!parse_int(value, 1, 65535, number)) {
                    add_problem(problems, origin, line_number, "invalid port: " + value);
                    return false;
                }
                m.kind = MatcherKind::port;
                m.port = static_cast<std::uint16_t>(number);
                rule.matchers.push_back(std::move(m));
                continue;
            }
            if (key == "proto" || key == "protocol") {
                m.kind = MatcherKind::protocol;
                if (lower(value) == "tcp") {
                    m.protocol = kProtoTcp;
                } else if (lower(value) == "udp") {
                    m.protocol = kProtoUdp;
                } else {
                    add_problem(problems, origin, line_number,
                                "protocol must be tcp or udp, got: " + value);
                    return false;
                }
                rule.matchers.push_back(std::move(m));
                continue;
            }
            add_problem(problems, origin, line_number, "unknown matcher prefix: " + key);
            return false;
        }

        // ---- action ----
        if (!have_action) {
            Strategy candidate{};
            const bool host_prefixed = !token.empty() &&
                                       (token[0] == '=' || token[0] == '*' || token[0] == '.');
            if (!host_prefixed && parse_strategy(token, candidate)) {
                rule.strategy = candidate;
                have_action = true;
                continue;
            }
            // ---- hostname matcher ----
            Matcher m;
            m.kind = MatcherKind::host_suffix;
            bool subdomains_only = false;
            const auto normalized = clean_domain_token(token, &subdomains_only);
            if (!normalized) {
                add_problem(problems, origin, line_number, "invalid hostname: " + token);
                return false;
            }
            // "=example.com" means the exact host only; everything else is a suffix rule.
            if (token.size() >= 1 && token[0] == '=') m.kind = MatcherKind::host_exact;
            m.subdomains_only = subdomains_only;
            m.text = lower(*normalized);
            rule.matchers.push_back(std::move(m));
            continue;
        }

        // ---- options ----
        if (eq == std::string::npos) {
            add_problem(problems, origin, line_number,
                        "unexpected token after the action: " + token);
            return false;
        }
        const std::string key = lower(token.substr(0, eq));
        const std::string value = token.substr(eq + 1);
        int number = 0;
        bool flag = false;
        if (key == "split" && parse_int(value, 1, 65535, number)) {
            rule.overrides.split_position = number;
        } else if (key == "splitpos" && parse_int(value, -1, 65535, number)) {
            rule.overrides.split_position = number;
        } else if (key == "ttl" && parse_int(value, 1, 255, number)) {
            rule.overrides.fake_ttl = number;
        } else if (key == "repeats" && parse_int(value, 1, 64, number)) {
            rule.overrides.repeats = number;
        } else if (key == "segs" && parse_int(value, 2, 16, number)) {
            rule.overrides.segments = number;
        } else if (key == "badseq" && parse_bool(value, flag)) {
            rule.overrides.fooling_badseq = flag;
        } else if (key == "badsum" && parse_bool(value, flag)) {
            rule.overrides.fooling_badsum = flag;
        } else if (key == "rnd" && parse_bool(value, flag)) {
            rule.overrides.randomize_random = flag;
        } else if (key == "priority" && parse_int(value, -1000, 1000, number)) {
            rule.priority = number;
        } else if ((key == "sni" || key == "fake-sni") && !value.empty()) {
            const auto fake = normalize_hostname(value);
            if (!fake) {
                add_problem(problems, origin, line_number, "invalid sni hostname: " + value);
                return false;
            }
            rule.overrides.fake_sni = lower(*fake);
        } else if (key == "name") {
            rule.name = value;
        } else {
            add_problem(problems, origin, line_number, "unknown option: " + key + "=" + value);
            return false;
        }
    }

    if (!have_action) {
        add_problem(problems, origin, line_number,
                    "expected an action: a strategy name or 'pass'");
        return false;
    }
    if (rule.matchers.empty()) {
        add_problem(problems, origin, line_number, "rule has no matcher");
        return false;
    }
    for (const Matcher& m : rule.matchers) {
        if (m.kind == MatcherKind::host_exact || m.kind == MatcherKind::host_suffix) {
            if (m.text.empty() || m.text.size() > 253) {
                add_problem(problems, origin, line_number, "hostname out of range: " + m.text);
                return false;
            }
        }
    }
    rules_.push_back(std::move(rule));
    return true;
}

bool RuleSet::load_file(const std::filesystem::path& path, std::vector<ConfigProblem>& problems,
                        int include_depth) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        add_problem(problems, path, 0, "cannot open file");
        return false;
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return load_text(buffer.str(), path, problems, include_depth);
}

bool RuleSet::load_exclude_file(const std::filesystem::path& path,
                                std::vector<ConfigProblem>& problems, int include_depth) {
    if (include_depth > kMaxIncludeDepth) {
        add_problem(problems, path, 0, "include nesting too deep");
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        add_problem(problems, path, 0, "cannot open file");
        return false;
    }
    bool ok = true;
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(in, line)) {
        ++line_number;
        const std::size_t comment = line.find_first_of("#;");
        if (comment != std::string::npos) line.resize(comment);
        line = trim(line);
        if (line.empty()) continue;

        if (line.rfind("include", 0) == 0) {
            const std::filesystem::path base =
                path.has_parent_path() ? path.parent_path() : std::filesystem::path(".");
            const std::size_t sp = line.find_first_of(" \t");
            if (sp == std::string::npos) {
                add_problem(problems, path, line_number, "include needs a path");
                ok = false;
                continue;
            }
            if (!load_exclude_file(base / trim(std::string_view(line).substr(sp)), problems,
                                   include_depth + 1)) {
                ok = false;
            }
            continue;
        }

        // The whole line is the domain source: a hosts-file line is "0.0.0.0 example.com"
        // and the leading address must not be mistaken for the domain.
        bool subdomains_only = false;
        const auto normalized = clean_domain_token(line, &subdomains_only);
        if (!normalized) continue;  // junk: not a domain entry
        const std::string host = lower(*normalized);
        if (subdomains_only) {
            subdomain_excludes_.push_back(host);
        } else {
            exact_excludes_.emplace(host, 0);
            suffix_excludes_.push_back(host);
        }
    }
    // Longest suffixes first so the common case terminates quickly.
    std::sort(suffix_excludes_.begin(), suffix_excludes_.end(),
              [](const std::string& a, const std::string& b) {
                  if (a.size() != b.size()) return a.size() > b.size();
                  return a < b;
              });
    std::sort(subdomain_excludes_.begin(), subdomain_excludes_.end(),
              [](const std::string& a, const std::string& b) {
                  if (a.size() != b.size()) return a.size() > b.size();
                  return a < b;
              });
    return ok;
}

// ---------------------------------------------------------------------------
// compiled index
// ---------------------------------------------------------------------------

void RuleSet::compile() {
    trie_.clear();
    trie_.emplace_back();
    exact_hosts_.clear();
    address_only_rules_.clear();

    for (std::size_t i = 0; i < rules_.size(); ++i) {
        const Rule& rule = rules_[i];
        if (!rule.requires_host()) {
            if (address_only_rules_.size() < kMaxAddressOnlyRules) {
                address_only_rules_.push_back(i);
            }
            continue;
        }
        for (const Matcher& m : rule.matchers) {
            if (m.kind == MatcherKind::host_exact) {
                exact_hosts_.emplace(m.text, i);
            } else if (m.kind == MatcherKind::host_suffix) {
                // Insert into the reversed-label trie so a lookup walks from the TLD
                // downwards and can stop at the most specific matching node.
                const std::vector<std::string> labels = split_labels(m.text);
                std::size_t node = 0;
                for (auto it = labels.rbegin(); it != labels.rend(); ++it) {
                    auto [child, inserted] = trie_[node].children.emplace(*it, trie_.size());
                    if (inserted) trie_.emplace_back();
                    node = child->second;
                }
                if (std::find(trie_[node].rules.begin(), trie_[node].rules.end(), i) ==
                    trie_[node].rules.end()) {
                    trie_[node].rules.push_back(i);
                }
            }
        }
    }
}

const Rule* RuleSet::better(const Rule* current, const Rule* candidate,
                            std::size_t current_suffix,
                                            std::size_t candidate_suffix) noexcept {
    if (candidate == nullptr) return current;
    if (current == nullptr) return candidate;
    if (candidate->priority != current->priority) {
        return candidate->priority > current->priority ? candidate : current;
    }
    if (candidate_suffix != current_suffix) {
        return candidate_suffix > current_suffix ? candidate : current;
    }
    return candidate->order < current->order ? candidate : current;
}

const Rule* RuleSet::best_host_rule(std::string_view host, const IpAddress& destination,
                                    std::uint16_t destination_port,
                                    std::uint8_t protocol) const noexcept {
    if (host.empty()) return nullptr;

    // Collect the candidate rules along the reversed-label path, then evaluate them from
    // the most specific (deepest) node upwards. Walking outwards and returning the first
    // hit would pick the *shortest* suffix, which is the opposite of what a user means.
    std::size_t candidates[kMaxHostCandidates];
    std::size_t depth[kMaxHostCandidates];
    std::size_t count = 0;

    auto collect = [&](std::size_t index, std::size_t specificity) {
        if (count >= kMaxHostCandidates) return;
        candidates[count] = index;
        depth[count] = specificity;
        ++count;
    };

    auto exact = exact_hosts_.find(std::string(host));
    if (exact != exact_hosts_.end()) collect(exact->second, host.size());

    const std::vector<std::string> labels = split_labels(std::string(host));
    std::size_t node = 0;
    std::size_t consumed = 0;
    for (auto it = labels.rbegin(); it != labels.rend(); ++it) {
        auto child = trie_[node].children.find(*it);
        if (child == trie_[node].children.end()) break;
        node = child->second;
        consumed += it->size() + (consumed == 0 ? 0 : 1);
        for (const std::size_t index : trie_[node].rules) {
            collect(index, consumed);
        }
    }

    const Rule* best = nullptr;
    std::size_t best_suffix = 0;
    for (std::size_t i = 0; i < count; ++i) {
        const Rule& candidate = rules_[candidates[i]];
        if (!candidate.satisfies(host, destination, destination_port, protocol)) continue;
        best = better(best, &candidate, best_suffix, depth[i]);
        best_suffix = depth[i];
    }
    return best;
}

const Rule* RuleSet::match(std::string_view raw_host, const IpAddress& destination,
                           std::uint16_t destination_port, std::uint8_t protocol) const noexcept {
    // Callers are expected to hand us a normalized hostname (the TLS and HTTP parsers
    // already produce one). Normalizing here as well keeps the engine correct when a rule
    // file or a test does not, and costs nothing on the common path.
    std::string normalized;
    std::string_view host = raw_host;
    bool needs_normalization = false;
    for (char c : raw_host) {
        if (c >= 'A' && c <= 'Z') {
            needs_normalization = true;
            break;
        }
    }
    if (!raw_host.empty() && raw_host.back() == '.') needs_normalization = true;
    if (needs_normalization) {
        normalized = raw_host;
        if (!normalized.empty() && normalized.back() == '.') normalized.pop_back();
        std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        host = normalized;
    }

    const Rule* host_rule =
        host.empty() ? nullptr : best_host_rule(host, destination, destination_port, protocol);

    const Rule* address_rule = nullptr;
    for (const std::size_t index : address_only_rules_) {
        const Rule& candidate = rules_[index];
        if (!candidate.satisfies(host, destination, destination_port, protocol)) continue;
        address_rule = better(address_rule, &candidate,
                              address_rule ? address_rule->host_suffix_length() : 0,
                              candidate.host_suffix_length());
    }

    // Host rules win ties against address rules because they are more specific about
    // what the user asked for; a higher explicit priority still overrides that.
    if (host_rule == nullptr) return address_rule;
    if (address_rule == nullptr) return host_rule;
    return better(host_rule, address_rule, host_rule->host_suffix_length(),
                  address_rule->host_suffix_length());
}

bool RuleSet::excluded(std::string_view host) const noexcept {
    if (host.empty()) return false;
    if (exact_excludes_.count(std::string(host)) != 0) return true;
    for (const std::string& suffix : suffix_excludes_) {
        if (host_matches_suffix(host, suffix, false)) return true;
    }
    // "*.example.com" excludes subdomains but not the bare domain.
    for (const std::string& suffix : subdomain_excludes_) {
        if (host_matches_suffix(host, suffix, true)) return true;
    }
    return false;
}

bool RuleSet::excluded(const IpAddress& destination) const noexcept {
    // Local, private and otherwise special-purpose destinations are never desynchronized.
    // This is deliberately unconditional: even an explicit rule must not be able to make
    // the tool rewrite loopback or link-local traffic.
    return destination.family == IpFamily::none || destination.is_loopback() ||
           destination.is_private() || destination.is_multicast() ||
           destination.is_unspecified() || destination.is_link_local() ||
           destination.is_reserved();
}

}  // namespace zc
