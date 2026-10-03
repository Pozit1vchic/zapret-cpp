#include "zc/stats.hpp"

#include <cstdio>

namespace zc {
namespace {

std::string row(const char* label, std::uint64_t value) {
    char buffer[96];
    std::snprintf(buffer, sizeof(buffer), "  %-28s %14llu\n", label,
                  static_cast<unsigned long long>(value));
    return buffer;
}

const char* protocol_name(Protocol protocol) noexcept {
    switch (protocol) {
    case Protocol::other: return "other";
    case Protocol::tls: return "tls-clienthello";
    case Protocol::tls_no_sni: return "tls-no-sni";
    case Protocol::tls_partial: return "tls-partial";
    case Protocol::http: return "http-request";
    case Protocol::quic_initial: return "quic-initial";
    case Protocol::quic_other: return "quic-other";
    }
    return "?";
}

}  // namespace

std::string Statistics::to_string(std::size_t active_flows) const {
    std::string out;
    out += "capture\n";
    out += row("packets received", packets_received);
    out += row("packets outbound", packets_outbound);
    out += row("packets passed through", packets_passed_through);
    out += row("ipv4 / ipv6", ipv4_packets);
    out += row("ipv6", ipv6_packets);
    out += row("parse failures", parse_failures[0] + parse_failures[1] + parse_failures[2] +
                                     parse_failures[3] + parse_failures[4] + parse_failures[5] +
                                     parse_failures[6] + parse_failures[7]);
    out += row("receive failures", receive_failures);
    out += "classification\n";
    for (std::size_t i = 0; i < classified.size(); ++i) {
        out += row(protocol_name(static_cast<Protocol>(i)), classified[i]);
    }
    out += row("tls client hellos", tls_clienthello_total);
    out += row("tls with sni", tls_with_sni);
    out += row("tls without sni", tls_without_sni);
    out += row("tls encrypted (ech)", tls_ech);
    out += row("tls sni via reassembly", tls_from_reassembly);
    out += row("quic initials", quic_initial_total);
    out += row("quic decrypt failures", quic_decrypt_failed);
    out += row("quic sni recovered", quic_sni_recovered);
    out += "policy\n";
    out += row("matched by a rule", matched);
    out += row("no rule matched (pass)", no_rule_matched);
    out += row("excluded by host list", excluded_by_list);
    out += row("excluded by address", excluded_by_address);
    out += row("--all-hosts bypasses", all_hosts_bypass);
    out += "transformation\n";
    out += row("flows desynchronized", flows_desynced);
    out += row("flows already handled", flows_already_handled);
    out += row("packets generated", packets_generated);
    out += row("decoy packets", trick_packets);
    out += row("send failures", send_failures);
    for (std::size_t i = 0; i < kStrategyCount; ++i) {
        if (strategy_hits[i] == 0) continue;
        out += row(strategy_name(static_cast<Strategy>(i)), strategy_hits[i]);
    }
    out += row("active flows", static_cast<std::uint64_t>(active_flows));
    return out;
}

}  // namespace zc
