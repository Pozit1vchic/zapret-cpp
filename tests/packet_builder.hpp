// Shared helpers for building synthetic packets in tests.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "zc/packet.hpp"

namespace zctest {

inline void push8(std::vector<std::uint8_t>& v, std::uint8_t b) { v.push_back(b); }

inline void push16(std::vector<std::uint8_t>& v, std::uint16_t x) {
    v.push_back(static_cast<std::uint8_t>(x >> 8));
    v.push_back(static_cast<std::uint8_t>(x & 0xffu));
}

inline void push24(std::vector<std::uint8_t>& v, std::uint32_t x) {
    v.push_back(static_cast<std::uint8_t>((x >> 16) & 0xffu));
    v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xffu));
    v.push_back(static_cast<std::uint8_t>(x & 0xffu));
}

inline void push32(std::vector<std::uint8_t>& v, std::uint32_t x) {
    v.push_back(static_cast<std::uint8_t>((x >> 24) & 0xffu));
    v.push_back(static_cast<std::uint8_t>((x >> 16) & 0xffu));
    v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xffu));
    v.push_back(static_cast<std::uint8_t>(x & 0xffu));
}

inline void push_text(std::vector<std::uint8_t>& v, std::string_view text) {
    for (char c : text) v.push_back(static_cast<std::uint8_t>(c));
}

struct TcpOptions {
    std::uint16_t source_port = 50000;
    std::uint16_t destination_port = 443;
    std::uint32_t sequence = 1000;
    std::uint32_t acknowledgment = 1;
    std::uint8_t flags = zc::kTcpPsh | zc::kTcpAck;
    std::uint8_t ttl = 64;
    std::uint16_t window = 0xffff;
    std::vector<std::uint8_t> options;
};

struct UdpOptions {
    std::uint16_t source_port = 50000;
    std::uint16_t destination_port = 443;
    std::uint8_t ttl = 64;
};

inline std::vector<std::uint8_t> build_ipv4(std::uint8_t protocol,
                                            std::span<const std::uint8_t> transport,
                                            std::uint8_t ttl, std::uint16_t frag = 0,
                                            const std::array<std::uint8_t, 4>& source = {10, 0, 0, 2},
                                            const std::array<std::uint8_t, 4>& destination = {93, 184, 216, 34}) {
    std::vector<std::uint8_t> packet;
    packet.reserve(20 + transport.size());
    push8(packet, 0x45);
    push8(packet, 0);
    push16(packet, static_cast<std::uint16_t>(20 + transport.size()));
    push16(packet, 0x1234);
    push16(packet, frag);
    push8(packet, ttl);
    push8(packet, protocol);
    push16(packet, 0);
    packet.insert(packet.end(), source.begin(), source.end());
    packet.insert(packet.end(), destination.begin(), destination.end());
    packet.insert(packet.end(), transport.begin(), transport.end());
    return packet;
}

inline std::vector<std::uint8_t> build_tcp(std::span<const std::uint8_t> payload,
                                           const TcpOptions& options = {}) {
    std::vector<std::uint8_t> tcp;
    const std::size_t header = 20 + options.options.size();
    push16(tcp, options.source_port);
    push16(tcp, options.destination_port);
    push32(tcp, options.sequence);
    push32(tcp, options.acknowledgment);
    push8(tcp, static_cast<std::uint8_t>((header / 4) << 4));
    push8(tcp, options.flags);
    push16(tcp, static_cast<std::uint16_t>(options.window));
    push16(tcp, 0);  // checksum placeholder
    push16(tcp, 0);  // urgent pointer
    tcp.insert(tcp.end(), options.options.begin(), options.options.end());
    tcp.insert(tcp.end(), payload.begin(), payload.end());
    return build_ipv4(zc::kProtoTcp, tcp, options.ttl);
}

inline std::vector<std::uint8_t> build_udp(std::span<const std::uint8_t> payload,
                                           const UdpOptions& options = {}) {
    std::vector<std::uint8_t> udp;
    push16(udp, options.source_port);
    push16(udp, options.destination_port);
    push16(udp, static_cast<std::uint16_t>(8 + payload.size()));
    push16(udp, 0);
    udp.insert(udp.end(), payload.begin(), payload.end());
    return build_ipv4(zc::kProtoUdp, udp, options.ttl);
}

// IPv6 with a chain of extension headers before the transport header.
inline std::vector<std::uint8_t> build_ipv6(std::uint8_t next_header,
                                            std::span<const std::uint8_t> transport,
                                            std::uint8_t hop_limit = 64,
                                            const std::array<std::uint8_t, 16>& source = {},
                                            const std::array<std::uint8_t, 16>& destination = {}) {
    std::array<std::uint8_t, 16> src = source;
    std::array<std::uint8_t, 16> dst = destination;
    if (src == std::array<std::uint8_t, 16>{}) src = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (dst == std::array<std::uint8_t, 16>{}) {
        dst = {0x26, 0x06, 0x28, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x68};
    }
    std::vector<std::uint8_t> packet;
    push32(packet, 0x60000000);
    push16(packet, static_cast<std::uint16_t>(transport.size()));
    push8(packet, next_header);
    push8(packet, hop_limit);
    packet.insert(packet.end(), src.begin(), src.end());
    packet.insert(packet.end(), dst.begin(), dst.end());
    packet.insert(packet.end(), transport.begin(), transport.end());
    return packet;
}

inline std::vector<std::uint8_t> build_ipv6_tcp(std::span<const std::uint8_t> payload,
                                                std::uint8_t hop_limit = 64) {
    std::vector<std::uint8_t> tcp;
    TcpOptions options;
    const std::size_t header = 20 + options.options.size();
    push16(tcp, options.source_port);
    push16(tcp, options.destination_port);
    push32(tcp, options.sequence);
    push32(tcp, options.acknowledgment);
    push8(tcp, static_cast<std::uint8_t>((header / 4) << 4));
    push8(tcp, options.flags);
    push16(tcp, static_cast<std::uint16_t>(options.window));
    push16(tcp, 0);
    push16(tcp, 0);
    tcp.insert(tcp.end(), payload.begin(), payload.end());
    return build_ipv6(zc::kProtoTcp, tcp, hop_limit);
}

inline std::vector<std::uint8_t> build_ipv6_udp(std::span<const std::uint8_t> payload,
                                                std::uint8_t hop_limit = 64) {
    std::vector<std::uint8_t> udp;
    UdpOptions options;
    push16(udp, options.source_port);
    push16(udp, options.destination_port);
    push16(udp, static_cast<std::uint16_t>(8 + payload.size()));
    push16(udp, 0);
    udp.insert(udp.end(), payload.begin(), payload.end());
    return build_ipv6(zc::kProtoUdp, udp, hop_limit);
}

// A minimal but structurally valid TLS ClientHello record carrying `sni`.
inline std::vector<std::uint8_t> build_client_hello(std::string_view sni,
                                                    bool with_extensions = true,
                                                    bool with_sni = true) {
    std::vector<std::uint8_t> body;
    push16(body, 0x0303);
    for (int i = 0; i < 32; ++i) body.push_back(static_cast<std::uint8_t>(i * 7 + 1));
    body.push_back(0x00);  // session id
    push16(body, 4);
    push16(body, 0x1301);
    push16(body, 0x1302);
    body.push_back(0x01);
    body.push_back(0x00);

    if (with_extensions) {
        const std::size_t ext_len_pos = body.size();
        push16(body, 0);
        const std::size_t ext_start = body.size();
        if (with_sni) {
            push16(body, 0x0000);
            push16(body, static_cast<std::uint16_t>(5 + sni.size()));
            push16(body, static_cast<std::uint16_t>(3 + sni.size()));
            body.push_back(0x00);
            push16(body, static_cast<std::uint16_t>(sni.size()));
            push_text(body, sni);
        }
        // An unknown extension to prove unknown types are skipped.
        push16(body, 0x1234);
        push16(body, 4);
        push32(body, 0xdeadbeef);
        const std::size_t ext_len = body.size() - ext_start;
        body[ext_len_pos] = static_cast<std::uint8_t>(ext_len >> 8);
        body[ext_len_pos + 1] = static_cast<std::uint8_t>(ext_len & 0xffu);
    }

    std::vector<std::uint8_t> record;
    push8(record, 0x16);
    push8(record, 0x03);
    push8(record, 0x01);
    push16(record, static_cast<std::uint16_t>(body.size() + 4));
    push8(record, 0x01);
    push24(record, static_cast<std::uint32_t>(body.size()));
    record.insert(record.end(), body.begin(), body.end());
    return record;
}

inline std::vector<std::uint8_t> build_http_request(std::string_view method,
                                                    std::string_view path,
                                                    std::string_view host,
                                                    std::string_view version = "HTTP/1.1") {
    std::vector<std::uint8_t> out;
    push_text(out, method);
    push_text(out, " ");
    push_text(out, path);
    push_text(out, " ");
    push_text(out, version);
    push_text(out, "\r\nHost: ");
    push_text(out, host);
    push_text(out, "\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n");
    return out;
}

// Deterministic PRNG so failures are reproducible.
class Rng {
public:
    explicit Rng(std::uint32_t seed) : state_(seed == 0 ? 1u : seed) {}
    std::uint32_t next() {
        state_ ^= state_ << 13;
        state_ ^= state_ >> 17;
        state_ ^= state_ << 5;
        return state_;
    }
    std::uint8_t byte() { return static_cast<std::uint8_t>(next() & 0xffu); }
    void fill(std::vector<std::uint8_t>& v) {
        for (std::uint8_t& b : v) b = byte();
    }
    std::uint32_t below(std::uint32_t n) { return n == 0 ? 0 : next() % n; }

private:
    std::uint32_t state_;
};

}  // namespace zctest
