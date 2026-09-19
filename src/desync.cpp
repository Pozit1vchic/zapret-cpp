#include "desync.hpp"

#include <chrono>
#include <cstdint>

namespace zc {

namespace {

std::uint32_t bswap32(std::uint32_t v) {
    return ((v & 0x000000ffu) << 24) | ((v & 0x0000ff00u) << 8) |
           ((v & 0x00ff0000u) >> 8) | ((v & 0xff000000u) >> 24);
}

std::uint32_t rand32() {
    static std::uint32_t state = [] {
        auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        return 0x9e3779b9u ^ static_cast<std::uint32_t>(now);
    }();
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

Packet make_segment(const Packet& base, const std::uint8_t* payload, std::size_t len,
                    std::uint32_t seq, std::uint8_t flags, int ttl, bool badseq) {
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

    if (badseq) {
        std::uint32_t bad = rand32();
        t->seq = bswap32(bad);
    }

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

int resolve_split_pos(int requested, const TlsClientHello& tls, std::size_t plen) {
    if (requested >= 0) {
        if (requested >= static_cast<int>(plen)) {
            return static_cast<int>(plen) - 1;
        }
        return requested;
    }

    if (tls.valid && tls.sni_length > 0) {
        int mid = static_cast<int>(tls.sni_offset + tls.sni_length / 2);
        if (mid >= 1 && mid < static_cast<int>(plen)) {
            return mid;
        }
    }

    int mid = static_cast<int>(plen / 2);
    return (mid < 1) ? 1 : mid;
}

std::vector<std::uint8_t> build_fake_payload(const std::uint8_t* pl, std::size_t plen,
                                             const TlsClientHello& tls, const Config& cfg) {
    std::vector<std::uint8_t> fake(pl, pl + plen);

    if (tls.valid && tls.sni_length > 0 && cfg.fake_mod_sni && !cfg.fake_sni.empty()) {
        const std::string& d = cfg.fake_sni;
        for (std::size_t i = 0; i < tls.sni_length; ++i) {
            fake[tls.sni_offset + i] = static_cast<std::uint8_t>(d[i % d.size()]);
        }
    }

    if (cfg.fake_mod_rnd) {
        for (std::size_t i = 0; i < fake.size(); ++i) {
            if (i >= tls.sni_offset && i < tls.sni_offset + tls.sni_length && cfg.fake_mod_sni) {
                continue;
            }
            fake[i] = static_cast<std::uint8_t>(rand32() & 0xff);
        }
    }

    return fake;
}

std::vector<Packet> do_split(const Packet& pkt, const std::uint8_t* pl, std::size_t plen,
                             std::uint32_t seq, std::uint8_t flags, int split, const Config&) {
    std::vector<Packet> out;
    out.push_back(make_segment(pkt, pl, split, seq, flags, -1, false));
    out.push_back(make_segment(pkt, pl + split, plen - split, seq + split, flags, -1, false));
    return out;
}

std::vector<Packet> do_disorder(const Packet& pkt, const std::uint8_t* pl, std::size_t plen,
                                std::uint32_t seq, std::uint8_t flags, int split, const Config&) {
    std::vector<Packet> out;
    out.push_back(make_segment(pkt, pl + split, plen - split, seq + split, flags, -1, false));
    out.push_back(make_segment(pkt, pl, split, seq, flags, -1, false));
    return out;
}

std::vector<Packet> do_multidisorder(const Packet& pkt, const std::uint8_t* pl, std::size_t plen,
                                     std::uint32_t seq, std::uint8_t flags, int split,
                                     const Config& cfg) {
    std::vector<Packet> out;

    int segs = cfg.disorder_segments;
    if (segs < 2) {
        segs = 2;
    }
    if (segs > 8) {
        segs = 8;
    }
    if (static_cast<std::size_t>(segs) > plen) {
        segs = static_cast<int>(plen);
    }
    if (segs < 2) {
        out.push_back(pkt);
        return out;
    }

    std::vector<std::pair<std::size_t, std::size_t>> parts;
    parts.reserve(segs);

    std::size_t first = (split >= 1) ? static_cast<std::size_t>(split) : plen / 2;
    if (first < 1) {
        first = 1;
    }
    if (first >= plen) {
        first = plen - 1;
    }
    parts.emplace_back(0, first);

    std::size_t remaining = plen - first;
    std::size_t chunk = remaining / static_cast<std::size_t>(segs - 1);
    if (chunk == 0) {
        chunk = 1;
    }
    std::size_t off = first;
    for (int i = 1; i < segs && off < plen; ++i) {
        std::size_t take = chunk;
        if (i == segs - 1 || off + take > plen) {
            take = plen - off;
        }
        parts.emplace_back(off, take);
        off += take;
    }

    for (std::size_t i = parts.size(); i-- > 0;) {
        const auto& part = parts[i];
        std::uint32_t s = seq + static_cast<std::uint32_t>(part.first);
        out.push_back(make_segment(pkt, pl + part.first, part.second, s, flags, -1, false));
    }

    return out;
}

std::vector<Packet> emit_with_repeats(const std::vector<Packet>& in, int repeats) {
    if (repeats <= 1) {
        return in;
    }
    std::vector<Packet> out;
    out.reserve(in.size() * static_cast<std::size_t>(repeats));
    for (int r = 0; r < repeats; ++r) {
        for (const Packet& p : in) {
            out.push_back(p);
        }
    }
    return out;
}

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
    int split = resolve_split_pos(cfg.split_pos, tls, plen);

    switch (cfg.strategy) {
    case Strategy::Split:
        out = do_split(pkt, pl, plen, seq, flags, split, cfg);
        break;

    case Strategy::Disorder:
        out = do_disorder(pkt, pl, plen, seq, flags, split, cfg);
        break;

    case Strategy::Multidisorder:
        out = do_multidisorder(pkt, pl, plen, seq, flags, split, cfg);
        break;

    case Strategy::FakeTtl: {
        std::vector<std::uint8_t> fake = build_fake_payload(pl, plen, tls, cfg);
        out.push_back(make_segment(pkt, fake.data(), fake.size(), seq, flags, cfg.fake_ttl,
                                   cfg.fooling_badseq));
        out.push_back(make_segment(pkt, pl, plen, seq, flags, -1, false));
        break;
    }

    case Strategy::FakeMultidisorder:
    case Strategy::FakeAuto: {
        std::vector<std::uint8_t> fake = build_fake_payload(pl, plen, tls, cfg);
        out.push_back(make_segment(pkt, fake.data(), fake.size(), seq, flags, cfg.fake_ttl,
                                   cfg.fooling_badseq));

        std::vector<Packet> core = do_multidisorder(pkt, pl, plen, seq, flags, split, cfg);
        out.insert(out.end(), core.begin(), core.end());
        break;
    }

    case Strategy::HttpSplit:
    case Strategy::HttpDisorder:
        out = do_split(pkt, pl, plen, seq, flags, split, cfg);
        break;

    case Strategy::FakeQuic:
        out.push_back(pkt);
        break;
    }

    return emit_with_repeats(out, cfg.repeats);
}

std::vector<Packet> apply_http_desync(const Packet& pkt, const Config& cfg,
                                      std::size_t header_split) {
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

    int split = (cfg.split_pos >= 0) ? cfg.split_pos : static_cast<int>(header_split);
    if (split < 1) {
        split = 1;
    }
    if (split >= static_cast<int>(plen)) {
        split = static_cast<int>(plen) - 1;
    }

    std::uint32_t seq = bswap32(pkt.tcp()->seq);
    std::uint8_t  flags = pkt.tcp()->flags;

    if (cfg.strategy == Strategy::HttpDisorder) {
        out = do_disorder(pkt, pl, plen, seq, flags, split, cfg);
    } else {
        out = do_split(pkt, pl, plen, seq, flags, split, cfg);
    }

    return emit_with_repeats(out, cfg.repeats);
}

bool is_quic_initial(const std::uint8_t* p, std::size_t n) {
    if (n < 6) {
        return false;
    }
    bool long_header = (p[0] & 0x80) != 0;
    if (!long_header) {
        return false;
    }
    std::uint32_t version = (static_cast<std::uint32_t>(p[1]) << 24) |
                            (static_cast<std::uint32_t>(p[2]) << 16) |
                            (static_cast<std::uint32_t>(p[3]) << 8) |
                            static_cast<std::uint32_t>(p[4]);
    if (version == 0) {
        return false;
    }
    std::uint8_t type = (p[0] >> 4) & 0x03;
    return type == 0x0;
}

std::vector<Packet> apply_quic_desync(const Packet& pkt, const Config& cfg) {
    std::vector<Packet> out;

    if (!pkt.is_udp() || pkt.udp() == nullptr) {
        out.push_back(pkt);
        return out;
    }

    const std::uint8_t* pl = pkt.payload();
    std::size_t plen = pkt.payload_len();
    if (plen == 0) {
        out.push_back(pkt);
        return out;
    }

    std::vector<std::uint8_t> fake(pl, pl + plen);
    for (std::size_t i = 0; i < fake.size(); ++i) {
        fake[i] = static_cast<std::uint8_t>(rand32() & 0xff);
    }

    Packet fakepkt = pkt;
    fakepkt.bytes.resize(pkt.l4_off() + pkt.l4_hdr_len());
    fakepkt.bytes.insert(fakepkt.bytes.end(), fake.begin(), fake.end());
    if (fakepkt.parse()) {
        if (fakepkt.is_ipv4() && fakepkt.ip()) {
            fakepkt.ip()->ttl = static_cast<std::uint8_t>(cfg.fake_ttl);
        } else if (fakepkt.is_ipv6() && fakepkt.ip6()) {
            fakepkt.ip6()->hop_limit = static_cast<std::uint8_t>(cfg.fake_ttl);
        }
        fakepkt.refresh_lengths_and_checksums();
        out.push_back(fakepkt);
    }

    out.push_back(pkt);
    return out;
}

}
