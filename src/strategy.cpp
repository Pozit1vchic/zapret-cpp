#include "zc/strategy.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "zc/http.hpp"
#include "zc/quic.hpp"
#include "zc/tls.hpp"

namespace zc {
namespace {

// A tiny xorshift so decoys are deterministic for a given seed and reproducible in
// tests. It is never used where cryptographic quality matters.
std::uint32_t next_random(std::uint32_t& state) noexcept {
    if (state == 0) state = 0x9e3779b9u;
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

std::uint8_t data_segment_flags(std::uint8_t original, bool logical_last) noexcept {
    if (logical_last) return original;
    // FIN and PSH describe the logical end of the stream, which only the last segment
    // in transmission order may carry.
    return static_cast<std::uint8_t>(original & ~(kTcpFin | kTcpPsh));
}

std::uint8_t decoy_flags(std::uint8_t original) noexcept {
    // A decoy must never look like a new connection or a teardown.
    return static_cast<std::uint8_t>(original & ~(kTcpSyn | kTcpFin | kTcpRst));
}

// Rewrite the IP (and UDP) length fields to match the buffer. Must happen before
// re-parsing: parse_packet() rejects a datagram whose declared length does not match its
// bytes, and a re-segmented packet is by definition a different size from the original.
void set_ip_lengths(std::span<std::uint8_t> data) noexcept {
    if (data.size() < 4) return;
    const std::uint8_t version = static_cast<std::uint8_t>(data[0] >> 4);
    if (version == 4) {
        write_be16(data, 2, static_cast<std::uint16_t>(data.size()));
        // The transport header follows the IP header immediately unless there are options.
        const std::size_t ihl = static_cast<std::size_t>(data[0] & 0x0fu) * 4u;
        if (ihl >= 20 && data.size() >= ihl && data[9] == kProtoUdp &&
            data.size() - ihl >= 8) {
            write_be16(std::span<std::uint8_t>(data).subspan(ihl), 4,
                       static_cast<std::uint16_t>(data.size() - ihl));
        }
    } else if (version == 6 && data.size() >= 48) {
        write_be16(data, 4, static_cast<std::uint16_t>(data.size() - 40));
        if (data[6] == kProtoUdp) {
            write_be16(std::span<std::uint8_t>(data).subspan(40), 4,
                       static_cast<std::uint16_t>(data.size() - 40));
        }
    }
}

// Build one output packet carrying `payload` at `sequence`.
bool make_segment(std::span<const std::uint8_t> packet, const PacketLayout& layout,
                  std::span<const std::uint8_t> payload, std::uint32_t sequence,
                  std::uint8_t flags, std::uint32_t out_ttl, bool badseq, bool badsum,
                  std::uint32_t& random_state, OutPacket& out) {
    const std::size_t header_len = layout.payload_offset;
    if (header_len > packet.size() || header_len + payload.size() > kMaxIpDatagram) return false;
    out.bytes.assign(packet.begin(), packet.begin() + static_cast<std::ptrdiff_t>(header_len));
    out.bytes.insert(out.bytes.end(), payload.begin(), payload.end());
    out.trick = out_ttl != 0 || badseq || badsum;

    set_ip_lengths(out.bytes);

    PacketLayout built;
    if (parse_packet(out.bytes, built) != ParseStatus::ok || !built.tcp) return false;
    built.tcp_sequence = sequence;

    std::span<std::uint8_t> tcp = std::span<std::uint8_t>(out.bytes)
                                       .subspan(built.l4_offset, built.wire_length - built.l4_offset);
    tcp[13] = flags;
    // The sequence number is what makes the reordering meaningful: the receiver must still
    // reassemble the stream.
    write_be32(tcp, 4, sequence);

    if (badseq) {
        // Far outside any plausible receive window, and randomised so repeated decoys do
        // not look identical.
        const std::uint32_t delta = 0x40000000u + (next_random(random_state) & 0x0000ffffu);
        const std::uint32_t bad = sequence + delta;
        write_be32(tcp, 4, bad);
        tcp[13] = decoy_flags(tcp[13]);
    }

    out.layout = built;
    if (!fixup_packet(out.bytes, out.layout)) return false;

    if (out_ttl != 0) {
        (void)set_hop_limit(out.bytes, out.layout, static_cast<std::uint8_t>(out_ttl));
    }
    if (badsum) {
        poison_transport_checksum(out.bytes, out.layout);
    }
    return true;
}

std::vector<std::uint8_t> build_decoy_payload(std::span<const std::uint8_t> payload,
                                              const PayloadHints& hints,
                                              const StrategySettings& settings,
                                              const TransformContext& context) {
    std::uint32_t rng = static_cast<std::uint32_t>(context.seed) | 1u;
    std::vector<std::uint8_t> out(payload.begin(), payload.end());

    // 1. Replace the hostname in place when we know exactly where it is. Keeping the
    //    byte length identical means every TLS/HTTP length field stays valid.
    if (hints.has_hostname && hints.host_offset <= out.size() &&
        hints.host_length <= out.size() - hints.host_offset && hints.host_length > 0) {
        std::string seed_sni = settings.fake_sni;
        if (settings.auto_decoy) {
            // Deterministic per real host: stable behaviour, no surprises between runs.
            static constexpr std::array<std::string_view, 6> kDecoys = {
                "www.google.com", "www.microsoft.com", "www.apple.com",
                "www.wikipedia.org", "www.cloudflare.com", "www.bing.com"};
            std::uint32_t h = 2166136261u;
            for (char c : context.host) {
                h ^= static_cast<unsigned char>(c);
                h *= 16777619u;
            }
            seed_sni = std::string(kDecoys[h % kDecoys.size()]);
        }
        if (const auto fitted = fit_hostname(seed_sni, hints.host_length)) {
            std::copy(fitted->begin(), fitted->end(),
                      out.begin() + static_cast<std::ptrdiff_t>(hints.host_offset));
        }
    } else if (hints.is_tls_client_hello) {
        // 2. A ClientHello we could not read a hostname out of (ECH, or the record was
        //    truncated). Emit a fresh, internally consistent ClientHello instead of
        //    copying undecodable bytes: a decoy that is not valid TLS teaches a
        //    fingerprinting DPI nothing and may reach the server.
        std::string seed_sni = settings.fake_sni;
        if (settings.auto_decoy && !context.host.empty()) {
            static constexpr std::array<std::string_view, 6> kDecoys = {
                "www.google.com", "www.microsoft.com", "www.apple.com",
                "www.wikipedia.org", "www.cloudflare.com", "www.bing.com"};
            std::uint32_t h = 2166136261u;
            for (char c : context.host) {
                h ^= static_cast<unsigned char>(c);
                h *= 16777619u;
            }
            seed_sni = std::string(kDecoys[h % kDecoys.size()]);
        }
        std::array<std::uint8_t, 512> built{};
        const std::size_t n = build_client_hello(built, seed_sni, next_random(rng));
        if (n > 0) {
            out.assign(built.begin(), built.begin() + static_cast<std::ptrdiff_t>(n));
        }
    }

    // 3. Optional ClientHello.random randomization. Only that 32-byte field: touching
    //    framing would break the decoy's own TLS structure.
    if (settings.randomize_random && !out.empty() && out[0] == 0x16 && out.size() >= 11) {
        for (std::size_t i = 11; i + 1 < out.size() && i < 43; ++i) {
            out[i] = static_cast<std::uint8_t>(next_random(rng) & 0xffu);
        }
    }
    return out;
}

void append_repeats(std::vector<OutPacket>& out, int repeats) {
    if (repeats <= 1) return;
    std::size_t extra = 0;
    for (const OutPacket& p : out) {
        if (p.trick) extra += static_cast<std::size_t>(repeats - 1);
    }
    if (extra == 0) return;
    const std::size_t original = out.size();
    out.reserve(original + extra);
    for (std::size_t i = 0; i < original; ++i) {
        if (!out[i].trick) continue;
        for (int r = 1; r < repeats; ++r) out.push_back(out[i]);
    }
}

bool emit_splits(std::span<const std::uint8_t> packet, const PacketLayout& layout,
                 std::span<const std::uint8_t> payload,
                 const std::vector<std::pair<std::size_t, std::size_t>>& parts, bool reverse,
                 std::uint32_t& rng, std::vector<OutPacket>& out) {
    const std::uint32_t base_sequence = layout.tcp_sequence;
    const std::uint8_t flags = layout.tcp_flags;
    std::size_t index = 0;
    const std::size_t count = parts.size();
    for (std::size_t i = 0; i < count; ++i) {
        index = reverse ? (count - 1 - i) : i;
        const auto& part = parts[index];
        const bool logical_last = part.first + part.second == payload.size();
        OutPacket segment;
        const std::uint8_t segment_flags = data_segment_flags(flags, logical_last);
        if (!make_segment(packet, layout, payload.subspan(part.first, part.second),
                          base_sequence + static_cast<std::uint32_t>(part.first), segment_flags,
                          0, false, false, rng, segment)) {
            return false;
        }
        out.push_back(std::move(segment));
    }
    return true;
}

std::vector<std::pair<std::size_t, std::size_t>> two_parts(std::size_t payload_length,
                                                           std::size_t cut) {
    return {{0, cut}, {cut, payload_length - cut}};
}

std::vector<std::pair<std::size_t, std::size_t>> n_parts(std::size_t payload_length,
                                                         std::size_t first_cut, int segments) {
    std::vector<std::pair<std::size_t, std::size_t>> parts;
    int count = std::clamp(segments, 2, 16);
    if (static_cast<std::size_t>(count) > payload_length) count = static_cast<int>(payload_length);
    parts.reserve(static_cast<std::size_t>(count));

    std::size_t first = std::clamp<std::size_t>(first_cut, 1, payload_length - 1);
    parts.emplace_back(0, first);
    std::size_t offset = first;
    const std::size_t slots = static_cast<std::size_t>(count - 1);
    for (std::size_t i = 0; i < slots && offset < payload_length; ++i) {
        const std::size_t left_slots = slots - i;
        const std::size_t left_bytes = payload_length - offset;
        const std::size_t take = (left_bytes + left_slots - 1) / left_slots;
        parts.emplace_back(offset, take);
        offset += take;
    }
    return parts;
}

}  // namespace

std::size_t resolve_split_offset(const StrategySettings& settings, const PayloadHints& hints,
                                 std::size_t payload_length) noexcept {
    if (payload_length < 2) return 0;
    if (settings.split_position > 0) {
        return std::min<std::size_t>(static_cast<std::size_t>(settings.split_position),
                                     payload_length - 1);
    }
    if (settings.split_position == 0) return 0;

    // Default: cut in the middle of the hostname so the DPI sees a truncated SNI while
    // the server still receives the whole thing.
    if (hints.has_hostname && hints.host_length >= 2) {
        const std::size_t mid = hints.host_offset + hints.host_length / 2;
        if (mid > 0 && mid < payload_length) return mid;
    }
    return payload_length / 2;
}

std::vector<OutPacket> transform_tcp(std::span<const std::uint8_t> packet,
                                     const PacketLayout& layout, Strategy strategy,
                                     const StrategySettings& settings,
                                     const PayloadHints& hints,
                                     const TransformContext& context) {
    std::vector<OutPacket> original_only;
    if (!layout.tcp || layout.payload_length == 0) {
        OutPacket passthrough;
        passthrough.bytes.assign(packet.begin(), packet.end());
        passthrough.layout = layout;
        original_only.push_back(std::move(passthrough));
        return original_only;
    }

    const std::span<const std::uint8_t> payload = packet.subspan(layout.payload_offset,
                                                                  layout.payload_length);
    std::uint32_t rng = static_cast<std::uint32_t>(context.seed) | 1u;
    const std::size_t cut = resolve_split_offset(settings, hints, layout.payload_length);
    const std::uint32_t decoy_ttl =
        settings.fake_ttl > 0 ? static_cast<std::uint32_t>(settings.fake_ttl) : 0u;

    std::vector<OutPacket> out;

    auto push_decoy = [&]() {
        const std::vector<std::uint8_t> decoy_payload =
            build_decoy_payload(payload, hints, settings, context);
        if (decoy_payload.empty()) return;
        OutPacket decoy;
        if (make_segment(packet, layout, decoy_payload, layout.tcp_sequence,
                         decoy_flags(layout.tcp_flags), decoy_ttl, settings.fooling_badseq,
                         settings.fooling_badsum, rng, decoy)) {
            out.push_back(std::move(decoy));
        }
    };

    const bool use_fake = strategy_uses_fake(strategy) && decoy_ttl != 0;
    if (use_fake) push_decoy();

    // `real_emitted` tracks whether the transformation already delivers the original
    // payload. A decoy-only strategy still owes the peer the real bytes.
    bool real_emitted = false;
    bool ok = true;
    switch (strategy) {
    case Strategy::pass:
        real_emitted = false;
        break;
    case Strategy::split:
    case Strategy::fake_split:
        ok = cut > 0 && cut < layout.payload_length &&
             emit_splits(packet, layout, payload, two_parts(layout.payload_length, cut), false,
                         rng, out);
        real_emitted = ok;
        break;
    case Strategy::disorder:
    case Strategy::fake_disorder:
        ok = cut > 0 && cut < layout.payload_length &&
             emit_splits(packet, layout, payload, two_parts(layout.payload_length, cut), true,
                         rng, out);
        real_emitted = ok;
        break;
    case Strategy::multisplit:
        ok = layout.payload_length >= 2 &&
             emit_splits(packet, layout, payload,
                         n_parts(layout.payload_length, cut, settings.segments), false, rng, out);
        real_emitted = ok;
        break;
    case Strategy::multidisorder:
    case Strategy::fake_multidisorder:
    case Strategy::fake_auto:
        ok = layout.payload_length >= 2 &&
             emit_splits(packet, layout, payload,
                         n_parts(layout.payload_length, cut, settings.segments), true, rng, out);
        real_emitted = ok;
        break;
    case Strategy::fake:
    case Strategy::quic_fake:
        real_emitted = false;
        break;
    }

    if (!ok) {
        // Nothing could be emitted (payload too small, unparsable, ...). Fail open: send
        // the original packet untouched rather than dropping it.
        OutPacket passthrough;
        passthrough.bytes.assign(packet.begin(), packet.end());
        passthrough.layout = layout;
        return {std::move(passthrough)};
    }

    if (!real_emitted) {
        OutPacket real;
        if (make_segment(packet, layout, payload, layout.tcp_sequence, layout.tcp_flags, 0, false,
                         false, rng, real)) {
            out.push_back(std::move(real));
        }
    }
    if (out.empty()) {
        // Nothing could be produced at all: fail open rather than dropping the packet.
        OutPacket passthrough;
        passthrough.bytes.assign(packet.begin(), packet.end());
        passthrough.layout = layout;
        return {std::move(passthrough)};
    }
    append_repeats(out, settings.repeats);
    return out;
}

std::vector<OutPacket> transform_udp(std::span<const std::uint8_t> packet,
                                     const PacketLayout& layout, Strategy strategy,
                                     const StrategySettings& settings, const PayloadHints& hints,
                                     const TransformContext& context, int udp_length_delta) {
    std::vector<OutPacket> out;
    std::uint32_t rng = static_cast<std::uint32_t>(context.seed) | 1u;

    if (strategy == Strategy::quic_fake && hints.is_quic_initial &&
        settings.fake_ttl > 0) {
        // A fully protected client Initial carrying a decoy SNI. A decoy that is only
        // "QUIC-looking" is useless; this one decodes correctly for any RFC 9001 peer.
        std::string decoy_sni = settings.fake_sni;
        if (settings.auto_decoy && !context.host.empty()) {
            static constexpr std::array<std::string_view, 6> kDecoys = {
                "www.google.com", "www.microsoft.com", "www.apple.com",
                "www.wikipedia.org", "www.cloudflare.com", "www.bing.com"};
            std::uint32_t h = 2166136261u;
            for (char c : context.host) {
                h ^= static_cast<unsigned char>(c);
                h *= 16777619u;
            }
            decoy_sni = std::string(kDecoys[h % kDecoys.size()]);
        }
        const std::size_t target = std::max<std::size_t>(kQuicMinimumInitialSize,
                                                         layout.payload_length);
        const auto decoy = build_quic_client_initial(decoy_sni, target, next_random(rng));
        if (!decoy.empty() && layout.payload_length + decoy.size() <= kMaxIpDatagram) {
            OutPacket fake;
            fake.bytes.assign(packet.begin(),
                              packet.begin() + static_cast<std::ptrdiff_t>(layout.payload_offset));
            fake.bytes.insert(fake.bytes.end(), decoy.begin(), decoy.end());
            // A decoy from a different source port cannot be mistaken for a retransmission
            // of the real connection by the peer.
            if (fake.bytes.size() >= layout.l4_offset + 4) {
                const std::uint16_t source_port =
                    static_cast<std::uint16_t>(1024 + (next_random(rng) % 60000));
                write_be16(std::span<std::uint8_t>(fake.bytes).subspan(layout.l4_offset), 0,
                           source_port);
            }
            if (parse_packet(fake.bytes, fake.layout) == ParseStatus::ok && fake.layout.udp) {
                fake.trick = true;
                (void)set_hop_limit(fake.bytes, fake.layout,
                                  static_cast<std::uint8_t>(settings.fake_ttl));
                (void)fixup_packet(fake.bytes, fake.layout);
                for (int r = 0; r < std::max(1, settings.repeats); ++r) {
                    out.push_back(fake);
                }
            }
        }
    }

    // The real packet, optionally with the UDP payload length shifted. Padding appends
    // zero bytes, which is legal for QUIC (PADDING frames); trimming removes them.
    OutPacket real;
    real.bytes.assign(packet.begin(), packet.end());
    real.layout = layout;
    if (udp_length_delta != 0 && real.layout.udp) {
        const std::size_t header = real.layout.payload_offset;
        const std::size_t body = real.bytes.size() - header;
        if (udp_length_delta > 0) {
            const std::size_t add = std::min<std::size_t>(
                static_cast<std::size_t>(udp_length_delta), kMaxIpDatagram - real.bytes.size());
            if (add > 0) real.bytes.insert(real.bytes.end(), add, 0x00);
        } else if (body > 1) {
            // Trimming must never reduce the payload to nothing: a zero-length UDP
            // datagram is silently destructive, so such a request is ignored and the
            // packet is passed through instead.
            const std::size_t drop = std::min<std::size_t>(
                static_cast<std::size_t>(-udp_length_delta), body - 1);
            if (drop > 0) real.bytes.resize(real.bytes.size() - drop);
        }
        PacketLayout rebuilt;
        set_ip_lengths(real.bytes);
        if (parse_packet(real.bytes, rebuilt) != ParseStatus::ok) {
            // The edited packet no longer parses; refuse to touch it.
            real.bytes.assign(packet.begin(), packet.end());
            real.layout = layout;
        } else {
            real.layout = rebuilt;
            (void)fixup_packet(real.bytes, real.layout);
        }
    }
    out.push_back(std::move(real));
    return out;
}

}  // namespace zc
