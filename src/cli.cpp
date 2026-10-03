#include "zc/cli.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <sstream>

namespace zc {
namespace {

constexpr const char* kVersion = "3.0.0";

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

bool parse_bool(std::string_view text, bool& out) {
    const std::string v = lower(trim(text));
    if (v == "1" || v == "true" || v == "yes" || v == "on") { out = true; return true; }
    if (v == "0" || v == "false" || v == "no" || v == "off") { out = false; return true; }
    return false;
}

bool parse_u64(std::string_view text, std::uint64_t& out) {
    const std::string v = trim(text);
    if (v.empty()) return false;
    std::uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(v.data(), v.data() + v.size(), value);
    if (ec != std::errc{} || ptr != v.data() + v.size()) return false;
    out = value;
    return true;
}

bool parse_ports(std::string_view text, std::vector<std::uint16_t>& out) {
    out.clear();
    std::size_t start = 0;
    const std::string s = trim(text);
    while (start <= s.size()) {
        const std::size_t comma = s.find(',', start);
        const std::string piece =
            trim(std::string_view(s).substr(start, comma == std::string::npos
                                                        ? std::string::npos
                                                        : comma - start));
        if (!piece.empty()) {
            // Accept a single "lo-hi" range as well as individual ports.
            const std::size_t dash = piece.find('-');
            const auto convert = [](const std::string& t, std::uint64_t& value) {
                return parse_u64(t, value) && value >= 1 && value <= 65535;
            };
            if (dash != std::string::npos) {
                std::uint64_t lo = 0;
                std::uint64_t hi = 0;
                if (!convert(piece.substr(0, dash), lo) ||
                    !convert(piece.substr(dash + 1), hi) || hi < lo || hi - lo > 1024) {
                    return false;
                }
                for (std::uint64_t p = lo; p <= hi; ++p) {
                    out.push_back(static_cast<std::uint16_t>(p));
                }
            } else {
                std::uint64_t value = 0;
                if (!convert(piece, value)) return false;
                out.push_back(static_cast<std::uint16_t>(value));
            }
        }
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return !out.empty();
}

// Applies one `key = value` pair. Shared by the config file and (for a subset) the CLI.
enum class ApplyResult { ok, unknown, bad_value };

ApplyResult apply_setting(Options& options, std::string_view section, std::string_view key,
                           std::string_view value, std::string& error) {
    const std::string k = lower(trim(key));
    const std::string s = lower(trim(section));
    bool flag = false;
    std::uint64_t number = 0;
    Strategy strategy{};

    auto need_bool = [&] {
        if (!parse_bool(value, flag)) {
            error = "expected a boolean for '" + k + "', got '" + std::string(value) + "'";
            return false;
        }
        return true;
    };
    auto need_number = [&] {
        if (!parse_u64(value, number)) {
            error = "expected a number for '" + k + "', got '" + std::string(value) + "'";
            return false;
        }
        return true;
    };

    if (k == "log_level" || k == "loglevel") {
        if (!zc::log::parse_level(trim(value), options.log_level)) {
            error = "unknown log level: " + std::string(value);
            return ApplyResult::bad_value;
        }
        return ApplyResult::ok;
    }
    if (k == "all_hosts" || k == "allhosts") {
        if (!need_bool()) return ApplyResult::bad_value;
        options.engine.scope = flag ? Scope::all_hosts : Scope::listed;
        return ApplyResult::ok;
    }
    if (k == "act_without_sni") {
        if (!need_bool()) return ApplyResult::bad_value;
        options.engine.act_without_sni = flag;
        options.act_without_sni_cli = flag;
        options.have_act_without_sni = true;
        return ApplyResult::ok;
    }
    if (k == "sni_wait" || k == "sniwait") {
        if (!need_number()) return ApplyResult::bad_value;
        options.engine.sni_wait_bytes = static_cast<std::size_t>(std::min<std::uint64_t>(number, 1u << 20));
        return ApplyResult::ok;
    }
    if (k == "strategy" || k == "default_strategy") {
        if (!parse_strategy(trim(value), strategy) || strategy == Strategy::pass) {
            error = "unknown strategy: " + std::string(value);
            return ApplyResult::bad_value;
        }
        options.engine.global_strategy = strategy;
        options.engine.settings.auto_decoy = strategy == Strategy::fake_auto;
        return ApplyResult::ok;
    }
    if (k == "ttl") {
        if (!need_number() || number < 1 || number > 255) {
            error = "ttl must be 1..255";
            return ApplyResult::bad_value;
        }
        options.engine.settings.fake_ttl = static_cast<int>(number);
        return ApplyResult::ok;
    }
    if (k == "repeats") {
        if (!need_number() || number < 1 || number > 64) {
            error = "repeats must be 1..64";
            return ApplyResult::bad_value;
        }
        options.engine.settings.repeats = static_cast<int>(number);
        return ApplyResult::ok;
    }
    if (k == "segments" || k == "segs") {
        if (!need_number() || number < 2 || number > 16) {
            error = "segs must be 2..16";
            return ApplyResult::bad_value;
        }
        options.engine.settings.segments = static_cast<int>(number);
        return ApplyResult::ok;
    }
    if (k == "split" || k == "split_position") {
        if (!parse_u64(value, number) || number > 65535) {
            if (lower(trim(value)) == "auto") {
                options.engine.settings.split_position = -1;
                return ApplyResult::ok;
            }
            error = "split must be 'auto' or 0..65535";
            return ApplyResult::bad_value;
        }
        options.engine.settings.split_position = static_cast<int>(number);
        return ApplyResult::ok;
    }
    if (k == "badseq") {
        if (!need_bool()) return ApplyResult::bad_value;
        options.engine.settings.fooling_badseq = flag;
        return ApplyResult::ok;
    }
    if (k == "badsum") {
        if (!need_bool()) return ApplyResult::bad_value;
        options.engine.settings.fooling_badsum = flag;
        return ApplyResult::ok;
    }
    if (k == "randomize_random" || k == "rnd") {
        if (!need_bool()) return ApplyResult::bad_value;
        options.engine.settings.randomize_random = flag;
        return ApplyResult::ok;
    }
    if (k == "fake_sni" || k == "sni") {
        options.engine.settings.fake_sni = trim(value);
        return ApplyResult::ok;
    }
    if (k == "tls") {
        if (!need_bool()) return ApplyResult::bad_value;
        options.engine.enable_tls = flag;
        return ApplyResult::ok;
    }
    if (k == "http") {
        if (!need_bool()) return ApplyResult::bad_value;
        options.engine.enable_http = flag;
        return ApplyResult::ok;
    }
    if (k == "quic") {
        if (!need_bool()) return ApplyResult::bad_value;
        options.engine.enable_quic = flag;
        return ApplyResult::ok;
    }
    if (k == "udp_length_delta" || k == "udplen") {
        std::string v = trim(value);
        bool negative = false;
        if (!v.empty() && (v[0] == '-' || v[0] == '+')) {
            negative = v[0] == '-';
            v = v.substr(1);
        }
        if (!parse_u64(v, number) || number > 4096) {
            error = "udplen must be -4096..4096";
            return ApplyResult::bad_value;
        }
        options.engine.udp_length_delta = static_cast<int>(negative ? -number : number);
        return ApplyResult::ok;
    }
    if (k == "stats") {
        if (!need_bool()) return ApplyResult::bad_value;
        options.stats = flag;
        return ApplyResult::ok;
    }
    if (k == "stats_interval") {
        if (!need_number()) return ApplyResult::bad_value;
        options.stats_interval_ms = number;
        return ApplyResult::ok;
    }
    if (k == "flow_capacity") {
        if (!need_number() || number < 16 || number > 1000000) {
            error = "flow_capacity must be 16..1000000";
            return ApplyResult::bad_value;
        }
        options.flow_capacity = number;
        return ApplyResult::ok;
    }
    if (k == "flow_ttl") {
        if (!need_number() || number < 1000 || number > 3600000) {
            error = "flow_ttl must be 1000..3600000 milliseconds";
            return ApplyResult::bad_value;
        }
        options.flow_ttl_ms = number;
        return ApplyResult::ok;
    }
    if (k == "flow_stream_budget") {
        if (!need_number() || number > (1u << 30)) {
            error = "flow_stream_budget must be <= 1 GiB";
            return ApplyResult::bad_value;
        }
        options.flow_stream_budget = static_cast<std::size_t>(number);
        return ApplyResult::ok;
    }
    if (k == "tcp_ports" || k == "tls_ports") {
        if (!parse_ports(value, options.tcp_ports)) {
            error = "invalid port list: " + std::string(value);
            return ApplyResult::bad_value;
        }
        return ApplyResult::ok;
    }
    if (k == "http_ports") {
        if (!parse_ports(value, options.http_tcp_ports)) {
            error = "invalid port list: " + std::string(value);
            return ApplyResult::bad_value;
        }
        return ApplyResult::ok;
    }
    if (k == "udp_ports" || k == "quic_ports") {
        if (!parse_ports(value, options.udp_ports)) {
            error = "invalid port list: " + std::string(value);
            return ApplyResult::bad_value;
        }
        return ApplyResult::ok;
    }
    if (k == "all_tcp") {
        if (!need_bool()) return ApplyResult::bad_value;
        options.all_tcp_ports = flag;
        return ApplyResult::ok;
    }
    if (k == "capture_loopback") {
        if (!need_bool()) return ApplyResult::bad_value;
        options.capture_loopback = flag;
        return ApplyResult::ok;
    }
    if (k == "priority") {
        if (!parse_u64(value, number) || number > 32767) {
            error = "priority must be 0..32767";
            return ApplyResult::bad_value;
        }
        options.priority = static_cast<std::int16_t>(number);
        return ApplyResult::ok;
    }
    if (k == "no_auto_files") {
        if (!need_bool()) return ApplyResult::bad_value;
        options.no_auto_files = flag;
        return ApplyResult::ok;
    }
    if (k == "rules") {
        options.rule_files.emplace_back(trim(value));
        return ApplyResult::ok;
    }
    if (k == "exclude") {
        options.exclude_files.emplace_back(trim(value));
        return ApplyResult::ok;
    }
    if (k == "hostlist") {
        options.hostlist_files.emplace_back(trim(value));
        return ApplyResult::ok;
    }
    (void)s;
    return ApplyResult::unknown;
}

}  // namespace

std::string version_text() { return std::string("zapret-cpp ") + kVersion; }

bool load_config_file(const std::filesystem::path& path, Options& options,
                      std::vector<std::string>& errors) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        errors.push_back("cannot open config file: " + path.string());
        return false;
    }
    std::string section = "core";
    std::string line;
    std::size_t line_number = 0;
    bool ok = true;
    while (std::getline(in, line)) {
        ++line_number;
        const std::size_t comment = line.find_first_of("#;");
        if (comment != std::string::npos) line.resize(comment);
        line = trim(line);
        if (line.empty()) continue;
        if (line.front() == '[') {
            const std::size_t close = line.find(']');
            if (close == std::string::npos) {
                errors.push_back(path.string() + ":" + std::to_string(line_number) +
                                 ": unterminated section header");
                ok = false;
                continue;
            }
            section = lower(trim(std::string_view(line).substr(1, close - 1)));
            continue;
        }
        const std::size_t equals = line.find('=');
        if (equals == std::string::npos) {
            errors.push_back(path.string() + ":" + std::to_string(line_number) +
                             ": expected key = value");
            ok = false;
            continue;
        }
        const std::string_view key = std::string_view(line).substr(0, equals);
        const std::string_view value = std::string_view(line).substr(equals + 1);
        std::string error;
        const ApplyResult result = apply_setting(options, section, key, value, error);
        if (result == ApplyResult::unknown) {
            errors.push_back(path.string() + ":" + std::to_string(line_number) +
                             ": unknown setting '" + std::string(key) + "'");
            ok = false;
        } else if (result == ApplyResult::bad_value) {
            errors.push_back(path.string() + ":" + std::to_string(line_number) + ": " + error);
            ok = false;
        } else {
            options.config_keys_used.push_back(std::string(section) + "." + std::string(key));
        }
    }
    return ok;
}

bool parse_command_line(int argc, char** argv, Options& options, std::string& error) {
    std::vector<std::string> args;
    args.reserve(static_cast<std::size_t>(argc > 1 ? argc - 1 : 0));
    for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);

    // A --config file is applied first so that explicit flags can override it.
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& arg = args[i];
        if (arg.rfind("--config=", 0) == 0) {
            options.config_file = arg.substr(9);
        } else if (arg == "--config" && i + 1 < args.size()) {
            options.config_file = args[++i];
        }
    }
    if (!options.config_file.empty()) {
        std::vector<std::string> errors;
        if (!load_config_file(options.config_file, options, errors)) {
            error = errors.empty() ? "invalid configuration file" : errors.front();
            for (std::size_t i = 1; i < errors.size(); ++i) error += "\n  " + errors[i];
            return false;
        }
    }

    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& arg = args[i];
        const std::size_t equals = arg.find('=');
        const std::string key = equals == std::string::npos ? arg : arg.substr(0, equals);
        const std::string value = equals == std::string::npos ? std::string() : arg.substr(equals + 1);
        auto need_value = [&](std::string& out) {
            if (!value.empty()) {
                out = value;
                return true;
            }
            if (i + 1 < args.size()) {
                out = args[++i];
                return true;
            }
            error = key + " needs a value";
            return false;
        };
        std::string setting_error;
        auto apply = [&](std::string_view name, std::string_view val) {
            const ApplyResult r = apply_setting(options, "core", name, val, setting_error);
            if (r == ApplyResult::unknown) {
                error = "unknown option: " + std::string(name);
                return false;
            }
            if (r == ApplyResult::bad_value) {
                error = setting_error;
                return false;
            }
            return true;
        };

        if (key == "--help" || key == "-h") {
            options.mode = RunMode::help;
            return true;
        }
        if (key == "--version") {
            options.mode = RunMode::version;
            return true;
        }
        if (key == "--check") {
            options.mode = RunMode::check;
            continue;
        }
        if (key == "--list-rules") {
            options.mode = RunMode::list_rules;
            continue;
        }
        if (key == "--config") {
            continue;  // already handled
        }
        if (key == "--rules") {
            std::string path;
            if (!need_value(path)) return false;
            options.rule_files.emplace_back(std::move(path));
            continue;
        }
        if (key == "--exclude") {
            std::string path;
            if (!need_value(path)) return false;
            options.exclude_files.emplace_back(std::move(path));
            continue;
        }
        if (key == "--hostlist") {
            std::string path;
            if (!need_value(path)) return false;
            options.hostlist_files.emplace_back(std::move(path));
            continue;
        }
        if (key == "--filter") {
            std::string text;
            if (!need_value(text)) return false;
            options.filter = std::move(text);
            options.filter_overridden = true;
            continue;
        }
        if (key == "--dry-run") {
            options.dry_run = true;
            continue;
        }
        if (key == "--all-hosts") {
            if (!apply("all_hosts", "true")) return false;
            continue;
        }
        if (key == "--listed") {
            if (!apply("all_hosts", "false")) return false;
            continue;
        }
        if (key == "--all-tcp") {
            if (!apply("all_tcp", "true")) return false;
            continue;
        }
        if (key == "--capture-loopback") {
            if (!apply("capture_loopback", "true")) return false;
            continue;
        }
        if (key == "--no-auto-files") {
            if (!apply("no_auto_files", "true")) return false;
            continue;
        }
        if (key == "--no-stats") {
            if (!apply("stats", "false")) return false;
            continue;
        }

        // Boolean convenience switches that map onto settings.
        static const char* const kBoolFlags[] = {"--tls", "--http", "--quic", "--badseq",
                                                 "--badsum", "--randomize-random", "--act-without-sni"};
        bool matched = false;
        for (const char* flag : kBoolFlags) {
            if (key == flag) {
                if (!apply(key.substr(2), "true")) return false;
                matched = true;
                break;
            }
        }
        if (matched) continue;

        // Everything else is `key=value` against the shared settings table.
        static const char* const kValueFlags[] = {
            "--strategy", "--log-level", "--sni-wait", "--ttl", "--repeats", "--segs", "--split",
            "--fake-sni", "--udplen", "--stats-interval", "--flow-capacity", "--flow-ttl",
            "--flow-stream-budget", "--tcp-ports", "--http-ports", "--udp-ports", "--priority",
            "--seed"};
        for (const char* flag : kValueFlags) {
            if (key == flag) {
                std::string text;
                if (!need_value(text)) return false;
                std::string name = key.substr(2);
                if (name == "log-level") name = "log_level";
                if (name == "sni-wait") name = "sni_wait";
                if (name == "fake-sni") name = "fake_sni";
                if (name == "udplen") name = "udplen";
                if (name == "stats-interval") name = "stats_interval";
                if (name == "flow-capacity") name = "flow_capacity";
                if (name == "flow-ttl") name = "flow_ttl";
                if (name == "flow-stream-budget") name = "flow_stream_budget";
                if (name == "tcp-ports") name = "tls_ports";
                if (name == "http-ports") name = "http_ports";
                if (name == "udp-ports") name = "quic_ports";
                if (name == "seed") name = "seed";
                if (!apply(name, text)) return false;
                matched = true;
                break;
            }
        }
        if (matched) continue;

        error = "unknown option: " + arg;
        return false;
    }
    return true;
}

std::string build_filter(const Options& options) {
    if (options.filter_overridden) return options.filter;

    auto port_clause = [](std::vector<std::uint16_t> ports) {
        std::string out;
        for (std::size_t i = 0; i < ports.size(); ++i) {
            if (i != 0) out += " or ";
            out += "tcp.DstPort == " + std::to_string(ports[i]);
        }
        return out;
    };

    std::string expression;
    if (options.all_tcp_ports) {
        expression = "tcp.PayloadLength > 0";
    } else {
        std::vector<std::uint16_t> ports = options.tcp_ports;
        if (options.engine.enable_http) {
            ports.insert(ports.end(), options.http_tcp_ports.begin(), options.http_tcp_ports.end());
        }
        expression = "tcp.PayloadLength > 0 and (" + port_clause(ports) + ")";
    }

    std::string out = "outbound";
    // Loopback traffic never leaves the machine, so a DPI cannot see it and rewriting it
    // only risks breaking local services.
    if (!options.capture_loopback) out += " and not ip.IsLoopback()";
    out += " and (" + expression + ")";

    if (options.engine.enable_quic) {
        std::string udp;
        for (std::size_t i = 0; i < options.udp_ports.size(); ++i) {
            if (i != 0) udp += " or ";
            udp += "udp.DstPort == " + std::to_string(options.udp_ports[i]);
        }
        if (!udp.empty()) {
            out += " or (outbound and not ip.IsLoopback() and udp.PayloadLength > 0 and (" + udp + "))";
        }
    }
    return out;
}

std::string usage_text(std::string_view executable) {
    std::string out;
    out += version_text() + "\n";
    out += "Native WinDivert DPI desynchronization engine (C++" "20).\n\n";
    out += "usage: ";
    out += executable;
    out += " [options]\n\n";
    out +=
        "Scope (the safe default touches nothing that no rule matches):\n"
        "  --listed               only rule-matched traffic is touched (default)\n"
        "  --all-hosts            DANGEROUS: also touch every TLS/HTTP/QUIC flow\n"
        "  --act-without-sni      with --all-hosts, also act when no hostname is known\n"
        "  --rules=FILE           load per-domain rules (repeatable)\n"
        "  --exclude=FILE         never touch domains listed here (repeatable)\n"
        "  --hostlist=FILE        treat these domains as rule-matched\n"
        "  --config=FILE          load settings from a config file\n"
        "  --no-auto-files        do not auto-load config/rules.txt and lists/exclude.txt\n"
        "  --list-rules           print the compiled rules and exit\n"
        "\n"
        "Strategy (defaults are only used when a rule selects them):\n"
        "  --strategy=NAME        pass split disorder multisplit multidisorder fake\n"
        "                         fake-split fake-disorder fake-multidisorder fake-auto\n"
        "                         quic-fake\n"
        "  --ttl=N                decoy TTL / hop limit, 1..255\n"
        "  --repeats=N            how many times a decoy is repeated, 1..64\n"
        "  --segs=N               segments for multisplit/multidisorder, 2..16\n"
        "  --split=auto|N         split offset inside the payload\n"
        "  --fake-sni=HOST        decoy hostname\n"
        "  --badseq               decoy gets an out-of-window sequence number\n"
        "  --badsum               decoy gets a deliberately wrong checksum\n"
        "  --randomize-random     randomize ClientHello.random in decoys\n"
        "  --udplen=N             pad or trim the QUIC UDP payload\n"
        "\n"
        "Capture:\n"
        "  --tcp-ports=LIST       TLS ports, e.g. 443,8443 or 5000-5010\n"
        "  --http-ports=LIST      clear-text HTTP ports\n"
        "  --udp-ports=LIST       QUIC ports\n"
        "  --all-tcp              inspect every outbound TCP port\n"
        "  --capture-loopback     also capture loopback (rarely wanted)\n"
        "  --filter=EXPR          replace the generated WinDivert filter entirely\n"
        "  --priority=N           WinDivert handle priority\n"
        "\n"
        "Protocols:\n"
        "  --tls / --http / --quic    enable or disable a classifier\n"
        "\n"
        "Diagnostics:\n"
        "  --check                verify runtime prerequisites, config and rules, then exit\n"
        "  --log-level=LEVEL      error warn info debug trace off (default info)\n"
        "  --stats / --no-stats   print counters on exit (default on)\n"
        "  --stats-interval=MS    also print counters every MS milliseconds\n"
        "  --dry-run              load and validate everything, print the plan, do not capture\n"
        "  --version              print the version\n"
        "  --help                 print this help\n";
    return out;
}

}  // namespace zc
