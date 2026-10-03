// Counters reported by `--stats` and in the shutdown summary.
//
// The point is diagnosability without packet-level logging: if a network is not being
// unblocked you can tell whether packets were never classified, were classified but
// matched no rule, or were matched and the strategy ran.
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "zc/packet.hpp"
#include "zc/rules.hpp"

namespace zc {

enum class Protocol : std::uint8_t {
    other = 0,
    tls,
    tls_no_sni,
    tls_partial,
    http,
    quic_initial,
    quic_other,
};

inline constexpr std::size_t kStrategyCount = 12;

struct Statistics {
    // Capture / parse
    std::uint64_t packets_received = 0;
    std::uint64_t packets_outbound = 0;
    std::uint64_t packets_passed_through = 0;
    std::array<std::uint64_t, 8> parse_failures{};  // indexed by ParseStatus
    std::uint64_t ipv4_packets = 0;
    std::uint64_t ipv6_packets = 0;

    // Classification
    std::array<std::uint64_t, 8> classified{};  // indexed by Protocol
    std::uint64_t tls_clienthello_total = 0;
    std::uint64_t tls_with_sni = 0;
    std::uint64_t tls_without_sni = 0;
    std::uint64_t tls_ech = 0;
    std::uint64_t tls_from_reassembly = 0;
    std::uint64_t quic_initial_total = 0;
    std::uint64_t quic_decrypt_failed = 0;
    std::uint64_t quic_sni_recovered = 0;

    // Policy
    std::uint64_t excluded_by_list = 0;
    std::uint64_t excluded_by_address = 0;
    std::uint64_t no_rule_matched = 0;
    std::uint64_t matched = 0;
    std::uint64_t all_hosts_bypass = 0;

    // Transformation
    std::uint64_t flows_desynced = 0;
    std::uint64_t flows_already_handled = 0;
    std::uint64_t packets_generated = 0;
    std::uint64_t trick_packets = 0;
    std::uint64_t strategy_hits[kStrategyCount] = {};

    // Transport
    std::uint64_t send_failures = 0;
    std::uint64_t receive_failures = 0;

    void add_parse_failure(ParseStatus status) noexcept {
        const auto index = static_cast<std::size_t>(status);
        if (index < parse_failures.size()) ++parse_failures[index];
    }
    void add_protocol(Protocol protocol) noexcept {
        const auto index = static_cast<std::size_t>(protocol);
        if (index < classified.size()) ++classified[index];
    }
    void add_strategy(Strategy strategy) noexcept {
        const auto index = static_cast<std::size_t>(strategy);
        if (index < kStrategyCount) ++strategy_hits[index];
    }
    [[nodiscard]] std::string to_string(std::size_t active_flows) const;
};

}  // namespace zc
