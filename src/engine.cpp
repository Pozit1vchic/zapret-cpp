#include "zc/engine.hpp"

#include <algorithm>

#include "zc/log.hpp"

namespace zc {
namespace {

FlowKey make_flow_key(const PacketLayout& layout) {
    FlowKey key;
    key.source = layout.source;
    key.destination = layout.destination;
    key.source_port = layout.source_port;
    key.destination_port = layout.destination_port;
    key.protocol = layout.protocol;
    return key;
}

std::uint32_t seed_for(std::uint64_t base, const FlowKey& key) {
    std::uint32_t s = static_cast<std::uint32_t>(base) ^ 0x9e3779b9u;
    for (int i = 0; i < 16; i += 4) {
        s = (s ^ key.source.bytes[static_cast<std::size_t>(i)]) * 16777619u;
        s = (s ^ key.destination.bytes[static_cast<std::size_t>(i)]) * 16777619u;
    }
    s = (s ^ key.source_port) * 16777619u;
    s = (s ^ key.destination_port) * 16777619u;
    s = (s ^ key.protocol) * 16777619u;
    return s == 0 ? 1u : s;
}

}  // namespace

StrategySettings Engine::settings_for(const Rule* rule) const {
    StrategySettings out = config_.settings;
    if (rule == nullptr) return out;
    const StrategyOverrides& o = rule->overrides;
    if (o.split_position) out.split_position = *o.split_position;
    if (o.fake_ttl) out.fake_ttl = *o.fake_ttl;
    if (o.repeats) out.repeats = *o.repeats;
    if (o.segments) out.segments = *o.segments;
    if (o.fooling_badseq) out.fooling_badseq = *o.fooling_badseq;
    if (o.fooling_badsum) out.fooling_badsum = *o.fooling_badsum;
    if (o.randomize_random) out.randomize_random = *o.randomize_random;
    if (o.fake_sni) out.fake_sni = *o.fake_sni;
    return out;
}

const Rule* Engine::find_rule(std::string_view host, const PacketLayout& layout) const {
    return rules_.match(host, layout.destination, layout.destination_port, layout.protocol);
}

Decision Engine::decide_tcp(std::span<const std::uint8_t> packet, const PacketLayout& layout,
                            FlowEntry& flow) {
    Decision decision;
    const std::span<const std::uint8_t> payload =
        packet.subspan(layout.payload_offset, layout.payload_length);

    PayloadHints hints;
    const TlsClientHello tls = parse_tls(payload);
    const HttpRequest http = config_.enable_http && !tls.is_tls ? parse_http(payload) : HttpRequest{};

    // --- resolve the hostname ---------------------------------------------
    std::string host;
    if (tls.has_sni) {
        host = tls.sni;
        hints.is_tls_client_hello = true;
        hints.has_hostname = tls.sni_length > 0;
        hints.host_offset = tls.sni_offset;
        hints.host_length = tls.sni_length;
        ++stats_.tls_with_sni;
        if (!flow.tcp_stream.started() && config_.sni_wait_bytes > 0) {
            flow.tcp_stream.push(layout.tcp_sequence, payload);
        }
    } else if (http.usable()) {
        host = http.host;
        hints.has_hostname = http.host_value_length > 0;
        hints.host_offset = http.host_value_offset;
        hints.host_length = http.host_value_length;
        flow.tcp_stream.reset();  // HTTP needs no reassembly
    } else if (tls.is_client_hello) {
        hints.is_tls_client_hello = true;
        ++stats_.tls_without_sni;
        if (tls.encrypted_client_hello) ++stats_.tls_ech;
        // Not a rule candidate yet. Feed the bounded reassembly buffer so that a
        // ClientHello split across segments can still be classified on a later segment.
        // We do NOT fall back to the global strategy here: a ClientHello we cannot read
        // is precisely the case that must pass through untouched.
        if (config_.sni_wait_bytes > 0) {
            flow.tcp_stream.push(layout.tcp_sequence, payload);
            const TlsClientHello reassembled = parse_tls(flow.tcp_stream.data());
            if (reassembled.has_sni) {
                host = reassembled.sni;
                hints.has_hostname = reassembled.sni_length > 0;
                hints.host_offset = layout.payload_offset + reassembled.sni_offset;
                hints.host_length = reassembled.sni_length;
                ++stats_.tls_from_reassembly;
                flow.host = host;
                flow.classified = true;
            }
        }
    }

    if (host.empty() && !flow.host.empty()) {
        host = flow.host;
    }
    if (!host.empty() && flow.host.empty()) {
        flow.host = host;
        flow.classified = true;
    }

    // --- classify ---------------------------------------------------------
    if (tls.is_client_hello) {
        decision.protocol = tls.has_sni ? Protocol::tls : Protocol::tls_no_sni;
        ++stats_.tls_clienthello_total;
        if (!tls.hello_complete) decision.protocol = Protocol::tls_partial;
    } else if (http.usable()) {
        decision.protocol = Protocol::http;
    } else {
        decision.protocol = Protocol::other;
    }

    // --- policy -----------------------------------------------------------
    decision.host = host;

    if (rules_.excluded(layout.destination)) {
        ++stats_.excluded_by_address;
        decision.reason = "address excluded";
        return decision;
    }
    if (!host.empty() && rules_.excluded(host)) {
        ++stats_.excluded_by_list;
        decision.reason = "host excluded";
        return decision;
    }

    const Rule* rule = find_rule(host, layout);
    decision.rule = rule;
    decision.strategy = rule != nullptr ? rule->strategy : config_.global_strategy;
    decision.settings = settings_for(rule);
    decision.settings.auto_decoy = decision.strategy == Strategy::fake_auto;

    if (rule != nullptr) {
        ++stats_.matched;
    } else {
        ++stats_.no_rule_matched;
        if (config_.scope != Scope::all_hosts) {
            // Fail open: nothing matched and global processing was not requested.
            decision.reason = host.empty() ? "no rule, hostname unknown" : "no rule matched";
            decision.action = Action::pass;
            decision.strategy = Strategy::pass;
            return decision;
        }
        ++stats_.all_hosts_bypass;
        if (host.empty() && !config_.act_without_sni) {
            decision.reason = "hostname unknown, --act-without-sni off";
            decision.action = Action::pass;
            decision.strategy = Strategy::pass;
            return decision;
        }
        decision.reason = "--all-hosts";
    }

    if (decision.strategy == Strategy::pass) {
        decision.reason = "rule says pass";
        decision.action = Action::pass;
        return decision;
    }

    // A UDP-only strategy on TCP is a configuration error; pass instead of guessing.
    if (decision.strategy == Strategy::quic_fake) {
        decision.reason = "strategy not applicable to TCP";
        decision.action = Action::pass;
        decision.strategy = Strategy::pass;
        return decision;
    }

    decision.action = Action::replace;
    decision.reason = rule != nullptr ? "rule matched" : "all-hosts";
    (void)packet;
    return decision;
}

Decision Engine::decide_udp(std::span<const std::uint8_t> packet, const PacketLayout& layout,
                            FlowEntry& flow) {
    Decision decision;
    const std::span<const std::uint8_t> payload =
        packet.subspan(layout.payload_offset, layout.payload_length);
    PayloadHints hints;

    const QuicPacket quic = parse_quic(payload);
    decision.protocol = Protocol::quic_other;
    if (!quic.valid || quic.type != QuicPacketType::initial) {
        decision.reason = "not a QUIC Initial";
        return decision;
    }
    hints.is_quic_initial = true;
    ++stats_.quic_initial_total;
    decision.protocol = Protocol::quic_initial;

    // Remove Initial protection and read the TLS ClientHello carried in CRYPTO frames.
    // Initial keys depend only on the Destination Connection ID, so this works for any
    // observer; it is what makes hostname rules possible for HTTP/3.
    std::string host;
    std::vector<std::uint8_t> frames;
    std::uint64_t packet_number = 0;
    if (decrypt_quic_initial(payload, quic, flow.largest_quic_packet_number, frames,
                             packet_number)) {
        if (packet_number > flow.largest_quic_packet_number) {
            flow.largest_quic_packet_number = packet_number;
        }
        flow.quic_crypto.adopt_connection(
            quic.version, payload.subspan(quic.dcid_offset, quic.dcid_length));
        if (flow.quic_crypto.add_frames(frames)) {
            if (flow.quic_crypto.client_hello_sni(host)) {
                ++stats_.quic_sni_recovered;
            } else {
                host.clear();
            }
        }
    } else {
        ++stats_.quic_decrypt_failed;
        // A datagram that looks like an Initial but does not authenticate is not a QUIC
        // Initial we should act on.
        decision.reason = "QUIC Initial failed authentication";
        return decision;
    }

    if (host.empty() && !flow.host.empty()) host = flow.host;
    if (!host.empty() && flow.host.empty()) {
        flow.host = host;
        flow.classified = true;
    }
    decision.host = host;

    if (rules_.excluded(layout.destination)) {
        ++stats_.excluded_by_address;
        decision.reason = "address excluded";
        return decision;
    }
    if (!host.empty() && rules_.excluded(host)) {
        ++stats_.excluded_by_list;
        decision.reason = "host excluded";
        return decision;
    }

    const Rule* rule = find_rule(host, layout);
    decision.rule = rule;
    decision.strategy = rule != nullptr ? rule->strategy : config_.global_strategy;
    decision.settings = settings_for(rule);
    decision.settings.auto_decoy = decision.strategy == Strategy::fake_auto;

    if (rule != nullptr) {
        ++stats_.matched;
    } else {
        ++stats_.no_rule_matched;
        if (config_.scope != Scope::all_hosts) {
            decision.reason = "no rule matched";
            decision.action = Action::pass;
            decision.strategy = Strategy::pass;
            return decision;
        }
        ++stats_.all_hosts_bypass;
    }

    if (decision.strategy == Strategy::pass) {
        decision.reason = "rule says pass";
        decision.action = Action::pass;
        return decision;
    }
    // Only the QUIC decoy makes sense on UDP; a TCP split would be meaningless.
    if (decision.strategy != Strategy::quic_fake) {
        decision.strategy = Strategy::quic_fake;
        decision.settings.auto_decoy = false;
        decision.settings.repeats = 1;
    }
    decision.action = Action::replace;
    decision.reason = rule != nullptr ? "rule matched" : "all-hosts";
    return decision;
}

EngineOutput Engine::process(std::span<const std::uint8_t> packet, bool outbound,
                              std::uint64_t now_ms_value) {
    EngineOutput output;
    ++stats_.packets_received;
    if (!outbound) return output;  // we only ever rewrite our own traffic
    ++stats_.packets_outbound;

    PacketLayout layout;
    const ParseStatus status = parse_packet(packet, layout);
    if (status != ParseStatus::ok) {
        stats_.add_parse_failure(status);
        return output;
    }
    if (layout.family == IpFamily::v4) {
        ++stats_.ipv4_packets;
    } else {
        ++stats_.ipv6_packets;
    }

    // Nothing to do for connection management packets.
    if (layout.tcp && (layout.tcp_flags & (kTcpSyn | kTcpRst | kTcpFin)) != 0 &&
        layout.payload_length == 0) {
        flows_.forget(make_flow_key(layout));
        return output;
    }
    if (layout.payload_length == 0) return output;

    const FlowKey key = make_flow_key(layout);
    bool created = false;
    const std::shared_ptr<FlowEntry> flow = flows_.touch(key, now_ms_value, created);
    if (!flow) return output;
    if (flow->desynced) {
        // A one-shot desync is applied at most once per flow, no matter how often the
        // ClientHello is retransmitted.
        ++stats_.flows_already_handled;
        return output;
    }

    Decision decision = layout.tcp ? decide_tcp(packet, layout, *flow)
                                   : decide_udp(packet, layout, *flow);
    stats_.add_protocol(decision.protocol);

    if (decision.action != Action::replace) {
        ZC_LOG_AT(zc::log::Level::debug,
                  decision.protocol == Protocol::other ? "unclassified packet passed through"
                                                       : ("passed through: " + decision.reason));
        return output;
    }

    stats_.add_strategy(decision.strategy);
    flow->desynced = true;
    ++stats_.flows_desynced;

    TransformContext context;
    context.host = decision.host;
    context.seed = seed_for(config_.seed, key);

    if (layout.tcp) {
        const std::span<const std::uint8_t> payload =
            packet.subspan(layout.payload_offset, layout.payload_length);
        // Recompute the hints for the exact bytes we are transforming.
        PayloadHints hints;
        const TlsClientHello tls = parse_tls(payload);
        if (tls.has_sni) {
            hints.has_hostname = true;
            hints.host_offset = tls.sni_offset;
            hints.host_length = tls.sni_length;
            hints.is_tls_client_hello = true;
        } else if (tls.is_client_hello) {
            hints.is_tls_client_hello = true;
        } else {
            const HttpRequest http = parse_http(payload);
            if (http.usable()) {
                hints.has_hostname = true;
                hints.host_offset = http.host_value_offset;
                hints.host_length = http.host_value_length;
            }
        }
        output.packets = transform_tcp(packet, layout, decision.strategy, decision.settings, hints,
                                       context);
    } else {
        const std::span<const std::uint8_t> payload =
            packet.subspan(layout.payload_offset, layout.payload_length);
        PayloadHints hints;
        hints.is_quic_initial = parse_quic(payload).type == QuicPacketType::initial;
        output.packets = transform_udp(packet, layout, decision.strategy, decision.settings, hints,
                                       context, config_.udp_length_delta);
    }

    stats_.packets_generated += output.packets.size();
    for (const OutPacket& p : output.packets) {
        if (p.trick) ++stats_.trick_packets;
    }

    ZC_LOG_AT(zc::log::Level::debug, decision.reason + " " +
                                     (decision.host.empty() ? "<no-host>" : decision.host) +
                                     " -> " + strategy_name(decision.strategy));
    output.action = Action::replace;
    output.decision = std::move(decision);
    return output;
}

std::vector<std::string> Engine::describe_rules() const {
    std::vector<std::string> lines;
    lines.reserve(rules_.rules().size() + 2);
    char buffer[512];
    for (const Rule& rule : rules_.rules()) {
        std::string matchers;
        for (const Matcher& m : rule.matchers) {
            if (!matchers.empty()) matchers += " AND ";
            switch (m.kind) {
            case MatcherKind::host_exact: matchers += "=" + m.text; break;
            case MatcherKind::host_suffix: matchers += m.text; break;
            case MatcherKind::address: matchers += "ip:" + m.address.to_string(); break;
            case MatcherKind::cidr: matchers += "cidr:" + m.network.to_string(); break;
            case MatcherKind::port: matchers += "port:" + std::to_string(m.port); break;
            case MatcherKind::protocol:
                matchers += std::string("proto:") +
                            (m.protocol == kProtoUdp ? "udp" : "tcp");
                break;
            case MatcherKind::none: break;
            }
        }
        std::snprintf(buffer, sizeof(buffer), "  pri=%-4d %-22s %-46s", rule.priority,
                      rule.name.empty() ? "-" : rule.name.c_str(), matchers.c_str());
        std::string line = buffer;
        line += " -> ";
        line += strategy_name(rule.strategy);
        const StrategyOverrides& o = rule.overrides;
        if (o.split_position) line += " split=" + std::to_string(*o.split_position);
        if (o.fake_ttl) line += " ttl=" + std::to_string(*o.fake_ttl);
        if (o.repeats) line += " repeats=" + std::to_string(*o.repeats);
        if (o.segments) line += " segs=" + std::to_string(*o.segments);
        if (o.fooling_badseq && *o.fooling_badseq) line += " badseq=1";
        if (o.fooling_badsum && *o.fooling_badsum) line += " badsum=1";
        if (o.fake_sni) line += " sni=" + *o.fake_sni;
        lines.push_back(std::move(line));
    }
    return lines;
}

}  // namespace zc
