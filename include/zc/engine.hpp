// The decision pipeline.
//
//   capture -> parse -> classify -> flow state -> rule match -> strategy -> transform
//           -> checksum fixup -> reinject
//
// The single most important property of this file is the default policy:
// unknown traffic is passed through untouched. Traffic is only touched when a rule
// matches, or when the user explicitly opted into global processing with --all-hosts.
// A partial ClientHello, an encrypted ClientHello, a QUIC packet we cannot decrypt and
// any parse failure all resolve to "pass", never to "apply the fallback strategy".
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "zc/flow.hpp"
#include "zc/http.hpp"
#include "zc/packet.hpp"
#include "zc/quic.hpp"
#include "zc/rules.hpp"
#include "zc/stats.hpp"
#include "zc/strategy.hpp"
#include "zc/tls.hpp"

namespace zc {

enum class Scope {
    // Only rule-matched traffic is touched. This is the default.
    listed = 0,
    // Every recognized TLS/HTTP/QUIC flow is touched with the global strategy. Opt-in.
    all_hosts,
};

struct EngineConfig {
    Scope scope = Scope::listed;

    Strategy global_strategy = Strategy::fake_multidisorder;
    StrategySettings settings{};

    bool enable_tls = true;
    bool enable_http = true;
    bool enable_quic = true;

    // How many bytes of a flow's first flight to keep while waiting for a ClientHello to
    // become complete. 0 disables reassembly and the engine then only looks at the bytes
    // present in the current segment.
    std::size_t sni_wait_bytes = 8192;
    // When a flow ends without a hostname: pass (safe) or use the global strategy.
    bool act_without_sni = false;

    int udp_length_delta = 0;
    std::uint64_t seed = 0x243f6a88u;
};

enum class Action : std::uint8_t {
    pass = 0,        // re-inject the original packet unchanged
    replace,         // re-inject the transformed packet list
    drop,            // never used by the current policies; kept explicit for clarity
};

struct Decision {
    Action action = Action::pass;
    Strategy strategy = Strategy::pass;
    StrategySettings settings{};
    Protocol protocol = Protocol::other;
    const Rule* rule = nullptr;
    std::string host;        // resolved hostname, empty when unknown
    std::string reason;      // short machine-friendly explanation for logs
};

struct EngineOutput {
    Action action = Action::pass;
    std::vector<OutPacket> packets;   // only populated when action == replace
    Decision decision;
};

// Result of analysing a single captured packet.
class Engine {
public:
    Engine(EngineConfig config, RuleSet rules, FlowTable& flows, Statistics& stats)
        : config_(std::move(config)), rules_(std::move(rules)), flows_(flows), stats_(stats) {}

    [[nodiscard]] EngineOutput process(std::span<const std::uint8_t> packet, bool outbound,
                                       std::uint64_t now_ms);

    [[nodiscard]] const RuleSet& rules() const noexcept { return rules_; }
    [[nodiscard]] const EngineConfig& config() const noexcept { return config_; }

    // Human-readable dump of the loaded rules, used by --list-rules.
    [[nodiscard]] std::vector<std::string> describe_rules() const;

private:
    [[nodiscard]] Decision decide_tcp(std::span<const std::uint8_t> packet,
                                      const PacketLayout& layout, FlowEntry& flow);
    [[nodiscard]] Decision decide_udp(std::span<const std::uint8_t> packet,
                                      const PacketLayout& layout, FlowEntry& flow);
    [[nodiscard]] StrategySettings settings_for(const Rule* rule) const;
    [[nodiscard]] const Rule* find_rule(std::string_view host, const PacketLayout& layout) const;

    EngineConfig config_;
    RuleSet rules_;
    FlowTable& flows_;
    Statistics& stats_;
};

}  // namespace zc
