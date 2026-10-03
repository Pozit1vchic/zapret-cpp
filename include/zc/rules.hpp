// Rule engine.
//
// Everything the engine decides is driven by an external configuration file; no domain
// list is baked into the binary. The file is parsed once at startup, validated with
// file/line diagnostics, and compiled into lookup structures that are cheap enough to
// consult for every candidate packet:
//
//   * hostnames go into an exact-match hash map plus a reversed-label trie, so a lookup
//     costs O(labels) instead of a linear scan over the list;
//   * CIDRs go into per-prefix-length sorted vectors searched by binary search;
//   * destination ports go into a sorted vector.
//
// Rule file syntax (see config/rules.txt for a commented example):
//
//   # comment, or ; comment
//   include <path glob>              merge another rule/list file
//   <matcher>... <action> [opt=val]...
//
// <matcher> forms, all optional but at least one required:
//   example.com        host and all subdomains
//   =example.com       host only, no subdomains
//   *.example.com      subdomains only
//   .example.com       subdomains only (hosts-file style)
//   ip:1.2.3.4         exact destination address
//   cidr:10.0.0.0/8    destination CIDR, IPv4 or IPv6
//   port:443           destination port
//   proto:tcp|udp      protocol
//
// <action> is either `pass` (never desynchronize) or a strategy name. Options are
// `split=N ttl=N repeats=N segs=N badseq=0|1 badsum=0|1 rnd=0|1 sni=HOST`.
// `priority=N` (higher wins) and `name=LABEL` (for diagnostics) are also accepted.
//
// Multiple matchers on one line are ANDed; separate lines are ORed. Ties are broken by
// priority, then by the longest matching hostname suffix, then by file order.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "zc/packet.hpp"

namespace zc {

enum class Strategy {
    pass = 0,   // explicit "do not touch"
    split,
    disorder,
    multisplit,
    multidisorder,
    fake,
    fake_split,
    fake_disorder,
    fake_multidisorder,
    fake_auto,
    quic_fake,
};

[[nodiscard]] const char* strategy_name(Strategy s) noexcept;
[[nodiscard]] bool parse_strategy(std::string_view name, Strategy& out) noexcept;
[[nodiscard]] bool strategy_uses_fake(Strategy s) noexcept;
[[nodiscard]] bool strategy_splits(Strategy s) noexcept;

// Knobs that can be overridden per rule. Unset fields inherit the command line value.
struct StrategyOverrides {
    std::optional<int> split_position;
    std::optional<int> fake_ttl;
    std::optional<int> repeats;
    std::optional<int> segments;
    std::optional<bool> fooling_badseq;
    std::optional<bool> fooling_badsum;
    std::optional<bool> randomize_random;
    std::optional<std::string> fake_sni;
};

enum class MatcherKind : std::uint8_t {
    none = 0,
    host_exact,     // =example.com
    host_suffix,    // example.com / *.example.com / .example.com
    address,        // ip:
    cidr,           // cidr:
    port,           // port:
    protocol,       // proto:
};

struct Matcher {
    MatcherKind kind = MatcherKind::none;
    std::string text;        // hostname, as written
    // Set for "*.example.com" / ".example.com": the rule matches subdomains but not the
    // bare domain. Getting this wrong would silently widen the rule to the bare domain.
    bool subdomains_only = false;
    IpAddress address{};     // address
    IpNetwork network{};     // cidr
    std::uint16_t port = 0;  // port
    std::uint8_t protocol = 0;
};

struct Rule {
    int priority = 0;
    std::size_t order = 0;  // file order, used as the final tie-break
    std::string name;       // diagnostics only
    std::vector<Matcher> matchers;
    Strategy strategy = Strategy::pass;
    StrategyOverrides overrides;

    [[nodiscard]] bool matches_host(std::string_view host) const noexcept;
    [[nodiscard]] bool requires_host() const noexcept;
    [[nodiscard]] std::size_t host_suffix_length() const noexcept;
    // Full conjunction check: every matcher on this rule must hold.
    [[nodiscard]] bool satisfies(std::string_view host, const IpAddress& destination,
                                 std::uint16_t destination_port,
                                 std::uint8_t protocol) const noexcept;
};

struct RuleMatch {
    const Rule* rule = nullptr;
    std::size_t suffix_length = 0;  // specificity of the hostname match
};

// Diagnostic produced while loading a configuration file.
struct ConfigProblem {
    std::filesystem::path file;
    std::size_t line = 0;
    std::string message;
    [[nodiscard]] std::string to_string() const;
};

class RuleSet {
public:
    // Parses `path` (and anything it `include`s). Returns false and fills `problems` on
    // the first error; a broken configuration must never be silently half-applied.
    bool load_file(const std::filesystem::path& path, std::vector<ConfigProblem>& problems,
                   int include_depth = 0);
    bool load_text(std::string_view text, const std::filesystem::path& origin,
                   std::vector<ConfigProblem>& problems, int include_depth = 0);

    // A plain list of domains that must never be touched. Accepts adblock (`||x^`),
    // hosts-file (`0.0.0.0 x`), wildcard (`*.x`) and bare domain forms.
    bool load_exclude_file(const std::filesystem::path& path,
                           std::vector<ConfigProblem>& problems, int include_depth = 0);

    [[nodiscard]] const Rule* match(std::string_view host, const IpAddress& destination,
                                    std::uint16_t destination_port,
                                    std::uint8_t protocol) const noexcept;

    [[nodiscard]] bool excluded(std::string_view host) const noexcept;
    [[nodiscard]] bool excluded(const IpAddress& destination) const noexcept;

    [[nodiscard]] const std::vector<Rule>& rules() const noexcept { return rules_; }
    [[nodiscard]] std::size_t exclude_count() const noexcept {
        return exact_excludes_.size() + subdomain_excludes_.size();
    }
    [[nodiscard]] std::size_t include_count() const noexcept { return include_count_; }
    [[nodiscard]] bool empty() const noexcept { return rules_.empty(); }

private:
    struct TrieNode {
        std::unordered_map<std::string, std::size_t> children;  // label -> node index
        std::vector<std::size_t> rules;                         // rules ending at this node
    };

    bool add_rule(Rule rule, std::vector<ConfigProblem>& problems,
                  const std::filesystem::path& file, std::size_t line);
    bool parse_rule_line(const std::string& line, const std::filesystem::path& origin,
                         std::size_t line_number, std::vector<ConfigProblem>& problems);
    void compile();

    // Most specific host rule that also satisfies its non-host matchers. At most
    // kMaxHostCandidates host candidates are examined so the walk stays bounded.
    static constexpr std::size_t kMaxHostCandidates = 8;
    [[nodiscard]] const Rule* best_host_rule(
        std::string_view host, const IpAddress& destination, std::uint16_t destination_port,
        std::uint8_t protocol) const noexcept;

    // Rules that carry no hostname matcher are evaluated directly. There are expected to
    // be very few of them, and the compiler caps the number.
    static constexpr std::size_t kMaxAddressOnlyRules = 256;
    std::vector<std::size_t> address_only_rules_;

    [[nodiscard]] static const Rule* better(const Rule* current, const Rule* candidate,
                                            std::size_t current_suffix,
                                            std::size_t candidate_suffix) noexcept;

    std::vector<Rule> rules_;
    std::vector<TrieNode> trie_;
    std::unordered_map<std::string, std::size_t> exact_hosts_;   // host -> rule index
    std::unordered_map<std::string, std::size_t> exact_excludes_;
    std::vector<std::string> suffix_excludes_;      // host and all subdomains
    std::vector<std::string> subdomain_excludes_;  // subdomains only ("*.x" / ".x")

    std::size_t include_count_ = 0;
};

// Helper used by the domain-list loader and by tests.
[[nodiscard]] std::optional<std::string> normalize_domain(std::string_view raw) noexcept;

}  // namespace zc
