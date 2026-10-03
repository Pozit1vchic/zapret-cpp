#include "zc/packet.hpp"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstring>

#include "zc/csum.hpp"

namespace zc {
namespace {

std::uint32_t ipv4_from_bytes(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

bool in_cidr4(const std::uint8_t* addr, std::uint32_t network, std::uint8_t prefix) noexcept {
    if (prefix > 32) return false;
    const std::uint32_t a = ipv4_from_bytes(addr);
    if (prefix == 0) return true;
    const std::uint32_t mask = 0xffffffffu << (32u - prefix);
    return (a & mask) == (network & mask);
}

void mask_bytes(std::uint8_t* p, std::size_t width, std::uint8_t prefix) noexcept {
    if (prefix > width * 8) prefix = static_cast<std::uint8_t>(width * 8);
    for (std::size_t i = 0; i < width; ++i) {
        const std::size_t bit_base = i * 8;
        if (bit_base + 8 <= prefix) continue;
        const std::uint8_t keep = prefix <= bit_base ? 0u
                                                      : static_cast<std::uint8_t>(prefix - bit_base);
        const std::uint8_t m = static_cast<std::uint8_t>(keep == 0 ? 0x00u : (0xffu << (8u - keep)) & 0xffu);
        p[i] = static_cast<std::uint8_t>(p[i] & m);
    }
}

// Walk IPv6 extension headers. `l4_offset` is advanced in place.
// Returns true when a terminal (non-extension) protocol was reached.
ParseStatus walk_ipv6_extensions(std::span<const std::uint8_t> data, std::uint8_t& proto,
                                 std::size_t& l4_offset, std::size_t wire_end,
                                 bool& atomic_fragment) noexcept {
    atomic_fragment = false;
    // RFC 8200 does not bound the chain; cap it so a malicious packet cannot make
    // us loop for an unbounded time or nest headers far beyond the datagram.
    for (int step = 0; step < 16; ++step) {
        const bool options = (proto == kProtoHopByHop || proto == kProtoRouting ||
                              proto == kProtoDstOpts);
        if (options) {
            if (l4_offset + 2 > wire_end) return ParseStatus::bad_extension_chain;
            const std::uint8_t next = data[l4_offset];
            const std::size_t ext_len =
                (static_cast<std::size_t>(data[l4_offset + 1]) + 1u) * 8u;
            if (ext_len < 8 || l4_offset + ext_len > wire_end) {
                return ParseStatus::bad_extension_chain;
            }
            proto = next;
            l4_offset += ext_len;
            continue;
        }
        if (proto == kProtoFragment) {
            if (l4_offset + 8 > wire_end) return ParseStatus::bad_extension_chain;
            const std::uint8_t next = data[l4_offset];
            const std::uint16_t off_flags = read_be16(data, l4_offset + 2);
            const bool more = (off_flags & 0x0001u) != 0;
            const std::uint16_t offset = static_cast<std::uint16_t>((off_flags & 0xfff8u) >> 3);
            if (offset != 0 || more) return ParseStatus::fragmented;
            // RFC 6946 atomic fragment: indistinguishable from an unfragmented
            // packet and safe to process.
            atomic_fragment = true;
            proto = next;
            l4_offset += 8;
            continue;
        }
        if (proto == kProtoAh) {
            if (l4_offset + 2 > wire_end) return ParseStatus::bad_extension_chain;
            const std::uint8_t next = data[l4_offset];
            const std::size_t ext_len =
                (static_cast<std::size_t>(data[l4_offset + 1]) + 2u) * 4u;
            if (ext_len < 8 || l4_offset + ext_len > wire_end) {
                return ParseStatus::bad_extension_chain;
            }
            proto = next;
            l4_offset += ext_len;
            continue;
        }
        return ParseStatus::ok;  // terminal protocol (TCP/UDP/ICMP/...)
    }
    return ParseStatus::bad_extension_chain;
}

// True when `text` ends in a dotted quad that follows a colon, i.e. the "IPv4-mapped"
// spelling "::ffff:192.0.2.1".
bool last_dot_is_trailing_v4(std::string_view text, std::size_t last_colon,
                             std::size_t first_dot) noexcept {
    if (first_dot == std::string_view::npos || last_colon == std::string_view::npos) return false;
    return first_dot > last_colon && first_dot + 1 < text.size();
}

// RFC 4291 section 2.2 textual representation: eight 16-bit groups in hex, with at most
// one "::" standing for a run of zero groups. The trailing 32 bits may also be written
// as a dotted quad (RFC 4291 appendix A, e.g. "::ffff:192.0.2.1").
IpAddress parse_ipv6(std::string_view text) noexcept {
    auto parse_groups = [](std::string_view part, std::uint16_t* out,
                           std::size_t capacity) -> std::size_t {
        std::size_t count = 0;
        std::size_t i = 0;
        while (i < part.size()) {
            if (count >= capacity) return capacity + 1;
            std::uint32_t value = 0;
            std::size_t digits = 0;
            while (i < part.size() && digits < 5) {
                const char c = part[i];
                std::uint32_t d = 0;
                if (c >= '0' && c <= '9') d = static_cast<std::uint32_t>(c - '0');
                else if (c >= 'a' && c <= 'f') d = static_cast<std::uint32_t>(c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') d = static_cast<std::uint32_t>(c - 'A' + 10);
                else break;
                value = (value << 4) | d;
                ++i;
                ++digits;
            }
            if (digits == 0 || digits > 4) return capacity + 1;
            out[count++] = static_cast<std::uint16_t>(value);
            if (i < part.size()) {
                if (part[i] != ':') return capacity + 1;
                ++i;
                if (i == part.size()) return capacity + 1;  // trailing single colon
            }
        }
        return count;
    };

    std::uint16_t left[8] = {};
    std::uint16_t right[8] = {};
    std::array<std::uint8_t, 16> out{};

    // A trailing dotted quad occupies the last two groups. Rewrite it into hex and parse
    // normally: trying to splice the two halves back together is where this goes wrong.
    const std::size_t last_colon = text.rfind(':');
    const std::size_t first_dot = text.find('.');
    if (last_dot_is_trailing_v4(text, last_colon, first_dot)) {
        const IpAddress v4 = IpAddress::parse(text.substr(last_colon + 1));
        if (v4.family != IpFamily::v4) return {};
        const std::uint16_t high =
            static_cast<std::uint16_t>((static_cast<std::uint16_t>(v4.bytes[12]) << 8) |
                                       v4.bytes[13]);
        const std::uint16_t low =
            static_cast<std::uint16_t>((static_cast<std::uint16_t>(v4.bytes[14]) << 8) |
                                       v4.bytes[15]);
        char tail[16];
        std::snprintf(tail, sizeof(tail), "%x:%x", high, low);
        std::string rewritten(text.substr(0, last_colon + 1));
        rewritten += tail;
        if (rewritten.size() > 45) return {};
        return parse_ipv6(std::string_view(rewritten));
    }

    const std::size_t gap = text.find("::");
    if (gap == std::string_view::npos) {
        if (parse_groups(text, left, 8) != 8) return {};
        for (std::size_t i = 0; i < 8; ++i) {
            out[i * 2] = static_cast<std::uint8_t>(left[i] >> 8);
            out[i * 2 + 1] = static_cast<std::uint8_t>(left[i] & 0xffu);
        }
    } else {
        if (text.find("::", gap + 1) != std::string_view::npos) return {};  // two gaps
        const std::string_view head = text.substr(0, gap);
        const std::string_view tail = text.substr(gap + 2);
        const std::size_t head_count = head.empty() ? 0 : parse_groups(head, left, 8);
        const std::size_t tail_count = tail.empty() ? 0 : parse_groups(tail, right, 8);
        if (head_count > 8 || tail_count > 8) return {};
        if (head_count + tail_count >= 8) return {};  // "::" must stand for >= 1 group
        const std::size_t fill = 8 - head_count - tail_count;
        std::size_t index = 0;
        for (std::size_t i = 0; i < head_count; ++i, ++index) {
            if (index >= 8) return {};
            out[index * 2] = static_cast<std::uint8_t>(left[i] >> 8);
            out[index * 2 + 1] = static_cast<std::uint8_t>(left[i] & 0xffu);
        }
        index += fill;
        if (index > 8) return {};
        for (std::size_t i = 0; i < tail_count; ++i, ++index) {
            if (index >= 8) return {};
            out[index * 2] = static_cast<std::uint8_t>(right[i] >> 8);
            out[index * 2 + 1] = static_cast<std::uint8_t>(right[i] & 0xffu);
        }
    }

    IpAddress address;
    address.family = IpFamily::v6;
    address.bytes = out;
    return address;
}

}  // namespace

// ---------------------------------------------------------------------------
// IpAddress
// ---------------------------------------------------------------------------

std::string IpAddress::to_string() const {
    if (family == IpFamily::v4) {
        std::string s;
        s.reserve(15);
        for (int i = 12; i < 16; ++i) {
            if (i != 12) s.push_back('.');
            s += std::to_string(bytes[static_cast<std::size_t>(i)]);
        }
        return s;
    }
    if (family == IpFamily::v6) {
        // RFC 5952 canonical form: lowercase hex, longest run of zero groups
        // compressed to "::".
        std::uint16_t groups[8];
        for (int i = 0; i < 8; ++i) {
            groups[i] = static_cast<std::uint16_t>((bytes[static_cast<std::size_t>(i * 2)] << 8) |
                                                   bytes[static_cast<std::size_t>(i * 2 + 1)]);
        }
        int best_start = -1, best_len = 0, cur_start = -1, cur_len = 0;
        for (int i = 0; i < 8; ++i) {
            if (groups[i] == 0) {
                if (cur_start < 0) { cur_start = i; cur_len = 0; }
                ++cur_len;
                if (cur_len > best_len) { best_len = cur_len; best_start = cur_start; }
            } else {
                cur_start = -1;
                cur_len = 0;
            }
        }
        if (best_len < 2) { best_start = -1; best_len = 0; }

        static const char* kHex = "0123456789abcdef";
        std::string s;
        s.reserve(45);
        for (int i = 0; i < 8; ++i) {
            if (best_start >= 0 && i == best_start) {
                s += "::";
                i += best_len - 1;
                continue;
            }
            if (!s.empty() && s.back() != ':') s.push_back(':');
            const std::uint16_t g = groups[i];
            if (g >= 0x1000) s.push_back(kHex[(g >> 12) & 0xf]);
            if (g >= 0x0100) s.push_back(kHex[(g >> 8) & 0xf]);
            if (g >= 0x0010) s.push_back(kHex[(g >> 4) & 0xf]);
            s.push_back(kHex[g & 0xf]);
        }
        if (s.empty()) s = "::";
        return s;
    }
    return {};
}

bool IpAddress::is_loopback() const noexcept {
    if (family == IpFamily::v4) return bytes[12] == 127 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] != 0;
    if (family == IpFamily::v6) {
        static constexpr std::uint8_t kLoop[15] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        return std::memcmp(bytes.data(), kLoop, 15) == 0 && bytes[15] == 1;
    }
    return false;
}

bool IpAddress::is_unspecified() const noexcept {
    if (family == IpFamily::none) return true;
    for (std::size_t i = 0; i < width(); ++i) {
        if (bytes[12 + i] != 0) return false;
    }
    return true;
}

bool IpAddress::is_multicast() const noexcept {
    if (family == IpFamily::v4) return bytes[12] >= 224 && bytes[12] <= 239;
    if (family == IpFamily::v6) return bytes[0] == 0xff;
    return false;
}

bool IpAddress::is_link_local() const noexcept {
    if (family == IpFamily::v4) return bytes[12] == 169 && bytes[13] == 254;
    if (family == IpFamily::v6) return bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80;
    return false;
}

bool IpAddress::is_private() const noexcept {
    if (family == IpFamily::v4) {
        const std::uint32_t a = ipv4_from_bytes(bytes.data() + 12);
        if ((a & 0xff000000u) == 0x0a000000u) return true;               // 10/8
        if ((a & 0xfff00000u) == 0xac100000u) return true;               // 172.16/12
        if ((a & 0xffff0000u) == 0xc0a80000u) return true;               // 192.168/16
        if ((a & 0xff000000u) == 0x64000000u) return true;               // 100.64/10 CGNAT
        if ((a & 0xffff0000u) == 0xa9fe0000u) return true;               // 169.254/16
        if ((a & 0xff000000u) == 0x7f000000u) return true;               // 127/8
        if (a == 0) return true;                                         // 0.0.0.0
        if ((a & 0xf0000000u) == 0xe0000000u) return true;               // 224/4 multicast
        if ((a & 0xf0000000u) == 0xf0000000u) return true;               // 240/4 reserved
        if ((a & 0xffff0000u) == 0xffff0000u) return true;               // broadcast
        return false;
    }
    if (family == IpFamily::v6) {
        // ::ffff:0:0/96 IPv4-mapped: classify by the embedded v4 address.
        static constexpr std::uint8_t kV4Mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (std::memcmp(bytes.data(), kV4Mapped, 12) == 0) {
            return IpAddress::from_v4(bytes.data() + 12).is_private();
        }
        if ((bytes[0] & 0xfe) == 0xfc) return true;                       // fc00::/7 ULA
        if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) return true;   // fe80::/10
        if (bytes[0] == 0xff) return true;                                // ff00::/8
        bool zero = true;
        for (std::size_t i = 0; i < 16 && zero; ++i) zero = bytes[i] == 0;
        if (zero) return true;                                            // ::
        if (bytes[15] == 1 && bytes[0] == 0) {                            // ::1
            bool head_zero = true;
            for (std::size_t i = 0; i < 15 && head_zero; ++i) head_zero = bytes[i] == 0;
            if (head_zero) return true;
        }
        return false;
    }
    return false;
}

bool IpAddress::is_reserved() const noexcept {
    if (family == IpFamily::v4) {
        const std::uint32_t a = ipv4_from_bytes(bytes.data() + 12);
        return (a & 0xf0000000u) == 0xf0000000u;
    }
    return false;
}

IpAddress IpAddress::parse(std::string_view text) noexcept {
    if (text.empty() || text.size() > 63) return {};
    // Bracketed IPv6 literal, as used in HTTP Host headers and URLs.
    if (text.size() >= 2 && text.front() == '[' && text.back() == ']') {
        text = text.substr(1, text.size() - 2);
    }
    if (text.find(':') != std::string_view::npos) {
        return parse_ipv6(text);
    }

    // IPv4 dotted quad, strictly four decimal octets.
    std::array<std::uint8_t, 4> out{};
    std::size_t octet = 0;
    std::size_t i = 0;
    while (i < text.size() && octet < 4) {
        std::uint32_t value = 0;
        std::size_t digits = 0;
        while (i < text.size() && text[i] >= '0' && text[i] <= '9') {
            value = value * 10 + static_cast<std::uint32_t>(text[i] - '0');
            if (value > 255) return {};
            ++i;
            ++digits;
        }
        if (digits == 0) return {};
        out[octet++] = static_cast<std::uint8_t>(value);
        if (i < text.size()) {
            if (text[i] != '.' || octet == 4) return {};
            ++i;
        }
    }
    if (octet != 4 || i != text.size()) return {};
    return IpAddress::from_v4(out.data());
}

// ---------------------------------------------------------------------------
// IpNetwork
// ---------------------------------------------------------------------------

bool IpNetwork::contains(const IpAddress& addr) const noexcept {
    if (address.family != addr.family) return false;
    if (address.family == IpFamily::v4) {
        // IPv4 addresses live in the last four bytes of the 16-byte array.
        return in_cidr4(addr.bytes.data() + 12, ipv4_from_bytes(address.bytes.data() + 12),
                        prefix_length);
    }
    if (address.family == IpFamily::v6) {
        if (prefix_length > 128) return false;
        std::array<std::uint8_t, 16> masked_addr = addr.bytes;
        std::array<std::uint8_t, 16> masked_net = address.bytes;
        mask_bytes(masked_addr.data(), 16, prefix_length);
        mask_bytes(masked_net.data(), 16, prefix_length);
        return masked_addr == masked_net;
    }
    return false;
}

std::optional<IpNetwork> IpNetwork::parse(std::string_view cidr) noexcept {
    const std::size_t slash = cidr.find('/');
    if (slash == std::string_view::npos) return std::nullopt;
    const IpAddress net = IpAddress::parse(cidr.substr(0, slash));
    if (net.family == IpFamily::none) return std::nullopt;
    const std::string_view len_text = cidr.substr(slash + 1);
    if (len_text.empty() || len_text.size() > 3) return std::nullopt;
    unsigned len = 0;
    for (char c : len_text) {
        if (c < '0' || c > '9') return std::nullopt;
        len = len * 10 + static_cast<unsigned>(c - '0');
    }
    const unsigned max_len = net.family == IpFamily::v4 ? 32u : 128u;
    if (len > max_len) return std::nullopt;
    IpNetwork result;
    result.address = net;
    result.prefix_length = static_cast<std::uint8_t>(len);
    return result;
}

std::string IpNetwork::to_string() const {
    return address.to_string() + "/" + std::to_string(static_cast<unsigned>(prefix_length));
}

// ---------------------------------------------------------------------------
// parse_packet
// ---------------------------------------------------------------------------

ParseStatus parse_packet(std::span<const std::uint8_t> data, PacketLayout& out) noexcept {
    out = PacketLayout{};

    if (data.size() < 20) return out.status = ParseStatus::too_short;

    const std::uint8_t version = static_cast<std::uint8_t>(data[0] >> 4);
    std::uint8_t proto = 0;
    std::size_t l4_offset = 0;
    bool atomic_fragment = false;

    if (version == 4) {
        const std::size_t ihl = static_cast<std::size_t>(data[0] & 0x0fu) * 4u;
        if (ihl < 20) return out.status = ParseStatus::bad_header;
        if (data.size() < ihl) return out.status = ParseStatus::too_short;
        const std::size_t total = read_be16(data, 2);
        if (total < ihl) return out.status = ParseStatus::bad_length;
        if (total > data.size()) return out.status = ParseStatus::bad_length;

        const std::uint16_t frag = read_be16(data, 6);
        // 0x2000 = MF, 0x1fff = fragment offset. 0x4000 (DF) is fine.
        if ((frag & 0x3fffu) != 0) return out.status = ParseStatus::fragmented;

        out.family = IpFamily::v4;
        out.ip_header_length = ihl;
        out.wire_length = total;
        out.protocol = data[9];
        out.ip_ttl = data[8];
        out.source = IpAddress::from_v4(data.data() + 12);
        out.destination = IpAddress::from_v4(data.data() + 16);
        proto = data[9];
        l4_offset = ihl;
    } else if (version == 6) {
        if (data.size() < 40) return out.status = ParseStatus::too_short;
        const std::size_t payload_len = read_be16(data, 4);
        if (payload_len == 0) {
            // Jumbograms require the Hop-by-Hop Jumbo Payload option and exceed any
            // buffer we will ever be given; refuse rather than mis-parse.
            return out.status = ParseStatus::bad_length;
        }
        const std::size_t total = 40u + payload_len;
        if (total > data.size()) return out.status = ParseStatus::bad_length;

        out.family = IpFamily::v6;
        out.ip_header_length = 40;
        out.wire_length = total;
        out.protocol = data[6];
        out.ip_ttl = data[7];
        out.source = IpAddress::from_v6(data.data() + 8);
        out.destination = IpAddress::from_v6(data.data() + 24);
        proto = data[6];
        l4_offset = 40;
        const ParseStatus st =
            walk_ipv6_extensions(data, proto, l4_offset, total, atomic_fragment);
        if (st != ParseStatus::ok) return out.status = st;
    } else {
        return out.status = ParseStatus::bad_version;
    }

    out.l4_offset = l4_offset;
    out.l4_header_length = 0;

    if (proto == kProtoTcp) {
        if (out.wire_length < l4_offset + 20) return out.status = ParseStatus::too_short;
        const std::size_t doff = static_cast<std::size_t>((data[l4_offset + 12] >> 4) & 0x0fu) * 4u;
        if (doff < 20) return out.status = ParseStatus::bad_header;
        if (out.wire_length < l4_offset + doff) return out.status = ParseStatus::bad_header;
        out.tcp = true;
        out.protocol = kProtoTcp;
        out.source_port = read_be16(data, l4_offset);
        out.destination_port = read_be16(data, l4_offset + 2);
        out.tcp_sequence = read_be32(data, l4_offset + 4);
        out.tcp_acknowledgment = read_be32(data, l4_offset + 8);
        out.tcp_flags = data[l4_offset + 13];
        out.l4_header_length = doff;
        out.payload_offset = l4_offset + doff;
        out.payload_length = out.wire_length - out.payload_offset;
        out.status = ParseStatus::ok;
        return out.status;
    }

    if (proto == kProtoUdp) {
        if (out.wire_length < l4_offset + 8) return out.status = ParseStatus::too_short;
        const std::size_t udp_len = read_be16(data, l4_offset + 4);
        // A UDP datagram cannot be shorter than its header, and cannot be longer
        // than the IP payload. Length 0 means "jumbogram" for IPv6 and is invalid
        // over IPv4; reject both.
        if (udp_len < 8) return out.status = ParseStatus::bad_length;
        if (udp_len > out.wire_length - l4_offset) return out.status = ParseStatus::bad_length;
        out.udp = true;
        out.protocol = kProtoUdp;
        out.source_port = read_be16(data, l4_offset);
        out.destination_port = read_be16(data, l4_offset + 2);
        out.l4_header_length = 8;
        out.payload_offset = l4_offset + 8;
        out.payload_length = udp_len - 8;
        out.status = ParseStatus::ok;
        return out.status;
    }

    return out.status = ParseStatus::unknown_protocol;
}

// ---------------------------------------------------------------------------
// mutation
// ---------------------------------------------------------------------------

bool fixup_packet(std::span<std::uint8_t> data, const PacketLayout& l) noexcept {
    if (!l.ok()) return false;
    if (data.size() < l.wire_length) return false;
    if (l.wire_length > kMaxIpDatagram) return false;
    if (l.l4_offset + 8 > l.wire_length) return false;

    const std::size_t upper_len = l.wire_length - l.l4_offset;
    if (upper_len > 0xffffu) return false;

    // Transport header must still fit.
    if (l.tcp && l.l4_header_length < 20) return false;
    if (l.udp && l.l4_header_length < 8) return false;
    if (l.l4_offset + l.l4_header_length > l.wire_length) return false;

    if (l.family == IpFamily::v4) {
        if (l.ip_header_length < 20 || data.size() < l.ip_header_length) return false;
        write_be16(data, 2, static_cast<std::uint16_t>(l.wire_length));
        // IPv4 header checksum over exactly the header, options included.
        write_be16(data, 10, 0);
        write_be16(data, 10, internet_checksum(data.first(l.ip_header_length)));
    } else if (l.family == IpFamily::v6) {
        if (data.size() < 40) return false;
        if (l.wire_length - 40u > 0xffffu) return false;
        write_be16(data, 4, static_cast<std::uint16_t>(l.wire_length - 40u));
    } else {
        return false;
    }

    if (l.udp) {
        std::span<std::uint8_t> udp = data.subspan(l.l4_offset, upper_len);
        write_be16(udp, 4, static_cast<std::uint16_t>(upper_len));
    }

    // Transport checksum over the pseudo header + transport header + payload.
    std::span<std::uint8_t> transport = data.subspan(l.l4_offset, upper_len);
    std::size_t cs_offset = 0;
    if (l.tcp) cs_offset = 16;
    else if (l.udp) cs_offset = 6;
    else return true;  // not a checksummed L4 protocol for us

    if (cs_offset >= upper_len) return false;
    write_be16(transport, cs_offset, 0);

    std::uint32_t seed = 0;
    if (l.family == IpFamily::v4) {
        seed = ones_sum(std::span<const std::uint8_t>(data.data() + 12, 8));
        seed += l.protocol;
        seed += static_cast<std::uint32_t>(upper_len & 0xffffu);
    } else {
        seed = ones_sum(data.subspan(8, 32));
        // IPv6 pseudo header carries a 32-bit upper-layer length.
        const std::uint32_t ul = static_cast<std::uint32_t>(upper_len);
        seed += (ul >> 16) & 0xffffu;
        seed += ul & 0xffffu;
        seed += l.protocol;
    }
    std::uint16_t cs = fold_sum(ones_sum(transport, seed));
    if (l.udp && cs == 0) cs = 0xffffu;  // RFC 768: 0 means "no checksum"
    write_be16(transport, cs_offset, cs);
    return true;
}

bool set_hop_limit(std::span<std::uint8_t> data, const PacketLayout& l, std::uint8_t value) noexcept {
    if (value == 0) return false;
    if (l.family == IpFamily::v4) {
        if (data.size() < 10) return false;
        data[8] = value;
        write_be16(data, 10, 0);
        write_be16(data, 10, internet_checksum(data.first(l.ip_header_length)));
        return true;
    }
    if (l.family == IpFamily::v6) {
        if (data.size() < 8) return false;
        data[7] = value;
        return true;
    }
    return false;
}

void poison_transport_checksum(std::span<std::uint8_t> data, const PacketLayout& l) noexcept {
    if (l.tcp) {
        if (data.size() >= l.l4_offset + 18) {
            write_be16(data, l.l4_offset + 16, read_be16(data, l.l4_offset + 16) ^ 0xffffu);
        }
    } else if (l.udp) {
        if (data.size() >= l.l4_offset + 8) {
            write_be16(data, l.l4_offset + 6, read_be16(data, l.l4_offset + 6) ^ 0xffffu);
        }
    }
}

}  // namespace zc
