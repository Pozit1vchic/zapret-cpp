#include "desync.hpp"

#include <cstdint>

namespace zc {

static std::uint32_t bswap32(std::uint32_t v) {
    return ((v & 0x000000ffu) << 24) | ((v & 0x0000ff00u) << 8) |
           ((v & 0x00ff0000u) >> 8) | ((v & 0xff000000u) >> 24);
}

static Packet make_segment(const Packet& base, const std::uint8_t* payload, std::size_t len,
                           std::uint32_t seq, std::uint8_t flags, int ttl) {
    Packet seg = base;
    std::size_t header_len = base.ip_hdr_len() + base.tcp_hdr_len();
    seg.bytes.resize(header_len);
    seg.bytes.insert(seg.bytes.end(), payload, payload + len);

    if (!seg.parse()) {
        return base;
    }

    TcpHdr* t = seg.tcp();
    t->seq = bswap32(seq);
    t->flags = flags;

    if (ttl >= 0) {
        if (seg.is_ipv4() && seg.ip()) {
            seg.ip()->ttl = static_cast<std::uint8_t>(ttl);
        } else if (seg.is_ipv6() && seg.ip6()) {
            seg.ip6()->hop_limit = static_cast<std::uint8_t>(ttl);
        }
    }

    seg.refresh_lengths_and_checksums();
    return seg;
}

std::vector<Packet> apply_desync(const Packet& pkt, const TlsClientHello& tls, const Config& cfg) {
    std::vector<Packet> out;

    if (!pkt.is_tcp() || pkt.tcp() == nullptr) {
        out.push_back(pkt);
        return out;
    }

    const std::uint8_t* pl = pkt.payload();
    std::size_t plen = pkt.payload_len();
    if (plen == 0) {
        out.push_back(pkt);
        return out;
    }

    std::uint32_t seq = bswap32(pkt.tcp()->seq);
    std::uint8_t  flags = pkt.tcp()->flags;

    int split = cfg.split_pos;
    if (split < 0) {
        std::size_t mid = tls.valid ? (tls.sni_offset + tls.sni_length / 2) : (plen / 2);
        if (mid < 1) {
            mid = 1;
        }
        if (mid >= plen) {
            mid = plen - 1;
        }
        split = static_cast<int>(mid);
    }
    if (split < 1) {
        split = 1;
    }
    if (split >= static_cast<int>(plen)) {
        split = static_cast<int>(plen) - 1;
    }

    switch (cfg.strategy) {
    case Strategy::Split:
        out.push_back(make_segment(pkt, pl, split, seq, flags, -1));
        out.push_back(make_segment(pkt, pl + split, plen - split, seq + split, flags, -1));
        break;

    case Strategy::Disorder:
        out.push_back(make_segment(pkt, pl + split, plen - split, seq + split, flags, -1));
        out.push_back(make_segment(pkt, pl, split, seq, flags, -1));
        break;

    case Strategy::FakeTtl: {
        std::vector<std::uint8_t> fake(pl, pl + plen);
        if (tls.valid && tls.sni_length > 0 && !cfg.fake_sni.empty()) {
            const std::string& d = cfg.fake_sni;
            for (std::size_t i = 0; i < tls.sni_length; ++i) {
                fake[tls.sni_offset + i] = static_cast<std::uint8_t>(d[i % d.size()]);
            }
        }
        out.push_back(make_segment(pkt, fake.data(), fake.size(), seq, flags, cfg.fake_ttl));
        out.push_back(make_segment(pkt, pl, plen, seq, flags, -1));
        break;
    }
    }

    return out;
}

}
