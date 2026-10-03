// Packet transformation: turns one original packet into the sequence of packets that
// actually goes on the wire.
//
// Pipeline position: capture -> parse -> classify -> flow state -> rule match ->
// strategy selection -> *transform* -> checksum fixup -> reinject.
//
// Rules that matter here:
//   * Real segments keep the original sequence numbers so the server reassembles the
//     stream normally; only the *order* and the *boundaries* change.
//   * A synthetic decoy must be rejected by the real server but still reach a DPI.
//     `badseq` puts its sequence number outside the receive window, `badsum` gives it a
//     wrong checksum and `ttl` makes it die on the first router.
//   * Nothing here invents protocol content: decoys are either the original bytes with
//     the hostname replaced at the same length, or a freshly built, internally
//     consistent TLS ClientHello / QUIC Initial.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "zc/packet.hpp"
#include "zc/rules.hpp"

namespace zc {

// Where in the payload the interesting hostname is, so a decoy can replace it in place
// and a split can land inside it.
struct PayloadHints {
    bool has_hostname = false;
    std::size_t host_offset = 0;
    std::size_t host_length = 0;
    bool is_tls_client_hello = false;
    bool is_quic_initial = false;
};

struct StrategySettings {
    int split_position = -1;  // -1 = automatic (middle of the hostname)
    int fake_ttl = 4;
    int repeats = 1;
    int segments = 4;
    bool fooling_badseq = false;
    bool fooling_badsum = false;
    bool randomize_random = false;
    std::string fake_sni = "www.google.com";
    bool auto_decoy = false;  // fake-auto: derive the decoy from the real hostname
};

// Everything the transform stage needs that is not in the packet itself.
struct TransformContext {
    std::string_view host;          // resolved hostname, empty when unknown
    std::uint64_t seed = 0;         // deterministic PRNG seed for reproducibility
    std::uint32_t out_ttl = 0;      // TTL/hop-limit for decoys, 0 = do not lower
};

// TCP: split / disorder / multisplit / multidisorder, optionally preceded by a decoy.
// Always returns at least one packet; the caller must be able to re-inject them all.
[[nodiscard]] std::vector<OutPacket> transform_tcp(std::span<const std::uint8_t> packet,
                                                    const PacketLayout& layout, Strategy strategy,
                                                    const StrategySettings& settings,
                                                    const PayloadHints& hints,
                                                    const TransformContext& context);

// UDP: currently only the QUIC Initial decoy and payload-length padding.
[[nodiscard]] std::vector<OutPacket> transform_udp(std::span<const std::uint8_t> packet,
                                                    const PacketLayout& layout, Strategy strategy,
                                                    const StrategySettings& settings,
                                                    const PayloadHints& hints,
                                                    const TransformContext& context,
                                                    int udp_length_delta);

// Resolve the split position for a payload, honouring an explicit request.
[[nodiscard]] std::size_t resolve_split_offset(const StrategySettings& settings,
                                               const PayloadHints& hints,
                                               std::size_t payload_length) noexcept;

}  // namespace zc
