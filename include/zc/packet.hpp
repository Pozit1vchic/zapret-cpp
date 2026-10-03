// IPv4 / IPv6 / TCP / UDP parsing and mutation.
//
// Design notes
//  * `parse_packet()` is a *pure* reader: it never resizes or mutates the caller's
//    buffer. The previous implementation silently truncated `bytes`, which made
//    "parse" a hidden mutation and broke the invariant that a parsed packet can be
//    re-injected byte-for-byte.
//  * A packet whose declared wire length exceeds the captured bytes is rejected
//    (`ParseStatus::truncated`). Re-injecting a truncated packet would produce a
//    malformed IP datagram on the wire.
//  * `wire_length` records the authoritative length taken from the IP header so
//    callers can re-inject exactly the declared number of bytes.
#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace zc {

inline constexpr std::size_t kMaxIpDatagram = 65535;

enum class IpFamily : std::uint8_t { none = 0, v4 = 4, v6 = 6 };

struct IpAddress {
    IpFamily family = IpFamily::none;
    // IPv4 is stored in bytes[12..15] so that comparison, hashing and masking are
    // uniform for both families.
    std::array<std::uint8_t, 16> bytes{};

    static IpAddress from_v4(const std::uint8_t* p) noexcept {
        IpAddress a;
        a.family = IpFamily::v4;
        for (int i = 0; i < 4; ++i) {
            a.bytes[12 + static_cast<std::size_t>(i)] = p[i];
        }
        return a;
    }
    static IpAddress from_v6(const std::uint8_t* p) noexcept {
        IpAddress a;
        a.family = IpFamily::v6;
        for (int i = 0; i < 16; ++i) {
            a.bytes[static_cast<std::size_t>(i)] = p[i];
        }
        return a;
    }
    static IpAddress parse(std::string_view text) noexcept;  // v4 or v6 literal, empty on failure

    [[nodiscard]] std::size_t width() const noexcept {
        return family == IpFamily::v4 ? 4u : (family == IpFamily::v6 ? 16u : 0u);
    }
    [[nodiscard]] const std::uint8_t* raw() const noexcept { return bytes.data(); }
    [[nodiscard]] std::string to_string() const;

    // True for ::1 / 127.0.0.0/8.
    [[nodiscard]] bool is_loopback() const noexcept;
    // Unspecified address (0.0.0.0 / ::).
    [[nodiscard]] bool is_unspecified() const noexcept;
    // RFC1918, RFC6598 CGNAT, RFC3927 link-local, RFC4193 ULA, IPv4-mapped variants.
    [[nodiscard]] bool is_private() const noexcept;
    // RFC3927 / RFC4291 link-local.
    [[nodiscard]] bool is_link_local() const noexcept;
    // 224.0.0.0/4, ff00::/8.
    [[nodiscard]] bool is_multicast() const noexcept;
    // 240.0.0.0/4 and friends.
    [[nodiscard]] bool is_reserved() const noexcept;

    friend bool operator==(const IpAddress&, const IpAddress&) = default;
};

struct IpNetwork {
    IpAddress address{};
    std::uint8_t prefix_length = 0;

    [[nodiscard]] bool contains(const IpAddress& addr) const noexcept;
    [[nodiscard]] static std::optional<IpNetwork> parse(std::string_view cidr) noexcept;
    [[nodiscard]] std::string to_string() const;
};

// --- protocol numbers / TCP flags -------------------------------------------
inline constexpr std::uint8_t kProtoTcp = 6;
inline constexpr std::uint8_t kProtoUdp = 17;
inline constexpr std::uint8_t kProtoHopByHop = 0;
inline constexpr std::uint8_t kProtoRouting = 43;
inline constexpr std::uint8_t kProtoFragment = 44;
inline constexpr std::uint8_t kProtoAh = 51;
inline constexpr std::uint8_t kProtoDstOpts = 60;
inline constexpr std::uint8_t kProtoNone = 59;

inline constexpr std::uint8_t kTcpFin = 0x01;
inline constexpr std::uint8_t kTcpSyn = 0x02;
inline constexpr std::uint8_t kTcpRst = 0x04;
inline constexpr std::uint8_t kTcpPsh = 0x08;
inline constexpr std::uint8_t kTcpAck = 0x10;
inline constexpr std::uint8_t kTcpUrg = 0x20;

// --- layout ------------------------------------------------------------------

enum class ParseStatus : std::uint8_t {
    ok = 0,
    too_short,          // fewer bytes than the minimum header
    bad_version,        // neither IPv4 nor IPv6
    bad_length,         // declared length impossible for the captured buffer
    bad_header,         // header length / offset field inconsistent
    fragmented,         // IP fragment we must not touch
    bad_extension_chain,
    unknown_protocol,   // parsed IP fine, but not TCP/UDP
};

// Result of reading a packet. `ok` is redundant with `status == ParseStatus::ok`
// but is kept because it makes the hot path branch-free-ish.
struct PacketLayout {
    ParseStatus status = ParseStatus::too_short;
    IpFamily family = IpFamily::none;
    std::uint8_t protocol = 0;

    bool tcp = false;
    bool udp = false;

    std::size_t ip_offset = 0;
    std::size_t ip_header_length = 0;
    std::size_t l4_offset = 0;
    std::size_t l4_header_length = 0;
    std::size_t payload_offset = 0;
    std::size_t payload_length = 0;
    std::size_t wire_length = 0;  // authoritative IP-level length in bytes

    IpAddress source{};
    IpAddress destination{};
    std::uint16_t source_port = 0;       // host order
    std::uint16_t destination_port = 0;  // host order
    std::uint32_t tcp_sequence = 0;       // host order
    std::uint32_t tcp_acknowledgment = 0;
    std::uint8_t tcp_flags = 0;
    std::uint8_t ip_ttl = 0;             // TTL for IPv4, Hop Limit for IPv6

    [[nodiscard]] bool ok() const noexcept { return status == ParseStatus::ok; }
    [[nodiscard]] std::size_t transport_length() const noexcept {
        return wire_length > l4_offset ? wire_length - l4_offset : 0;
    }
    [[nodiscard]] std::span<const std::uint8_t> payload(std::span<const std::uint8_t> data) const noexcept {
        return data.subspan(payload_offset, payload_length);
    }
};

[[nodiscard]] ParseStatus parse_packet(std::span<const std::uint8_t> data,
                                       PacketLayout& out) noexcept;

[[nodiscard]] inline std::uint16_t read_be16(std::span<const std::uint8_t> d,
                                             std::size_t off) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(d[off]) << 8) |
                                      static_cast<std::uint16_t>(d[off + 1]));
}
[[nodiscard]] inline std::uint32_t read_be24(std::span<const std::uint8_t> d,
                                             std::size_t off) noexcept {
    return (static_cast<std::uint32_t>(d[off]) << 16) |
           (static_cast<std::uint32_t>(d[off + 1]) << 8) |
           static_cast<std::uint32_t>(d[off + 2]);
}
[[nodiscard]] inline std::uint32_t read_be32(std::span<const std::uint8_t> d,
                                             std::size_t off) noexcept {
    return (static_cast<std::uint32_t>(d[off]) << 24) |
           (static_cast<std::uint32_t>(d[off + 1]) << 16) |
           (static_cast<std::uint32_t>(d[off + 2]) << 8) |
           static_cast<std::uint32_t>(d[off + 3]);
}
inline void write_be16(std::span<std::uint8_t> d, std::size_t off, std::uint16_t v) noexcept {
    d[off] = static_cast<std::uint8_t>(v >> 8);
    d[off + 1] = static_cast<std::uint8_t>(v & 0xffu);
}
inline void write_be32(std::span<std::uint8_t> d, std::size_t off, std::uint32_t v) noexcept {
    d[off] = static_cast<std::uint8_t>((v >> 24) & 0xffu);
    d[off + 1] = static_cast<std::uint8_t>((v >> 16) & 0xffu);
    d[off + 2] = static_cast<std::uint8_t>((v >> 8) & 0xffu);
    d[off + 3] = static_cast<std::uint8_t>(v & 0xffu);
}

// --- mutation ----------------------------------------------------------------

// Recompute every length field and checksum implied by `l` after the payload has
// been edited. Returns false (and leaves the buffer usable but unfixed) when the
// buffer cannot represent a valid packet.
[[nodiscard]] bool fixup_packet(std::span<std::uint8_t> data, const PacketLayout& l) noexcept;

// Set IPv4 TTL / IPv6 Hop Limit. Returns false for a non-IP buffer.
[[nodiscard]] bool set_hop_limit(std::span<std::uint8_t> data, const PacketLayout& l,
                                 std::uint8_t value) noexcept;

// Deliberately write a wrong TCP/UDP checksum ("badsum" fooling).
void poison_transport_checksum(std::span<std::uint8_t> data, const PacketLayout& l) noexcept;

// --- owned packet ------------------------------------------------------------

// Output packet produced by the transformation stage.
struct OutPacket {
    std::vector<std::uint8_t> bytes;
    PacketLayout layout{};
    bool trick = false;  // synthetic decoy, not an original segment

    [[nodiscard]] bool empty() const noexcept { return bytes.empty(); }
};

}  // namespace zc
