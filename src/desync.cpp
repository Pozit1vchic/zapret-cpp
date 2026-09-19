#include "desync.hpp"

#include <chrono>
#include <cstdint>
#include <cstring>

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
                             std::uint32_t seq, std::uint8_t flags, int split, const Config& cfg) {
    std::vector<Packet> out;
    out.push_back(make_segment(pkt, pl, split, seq, flags, -1, cfg.fooling_badseq));
    out.push_back(make_segment(pkt, pl + split, plen - split, seq + split, flags, -1, false));
    return out;
}

std::vector<Packet> do_disorder(const Packet& pkt, const std::uint8_t* pl, std::size_t plen,
                                std::uint32_t seq, std::uint8_t flags, int split, const Config& cfg) {
    std::vector<Packet> out;
    out.push_back(make_segment(pkt, pl + split, plen - split, seq + split, flags, -1, false));
    out.push_back(make_segment(pkt, pl, split, seq, flags, -1, cfg.fooling_badseq));
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
        bool reverse_tail = (i + 1 < parts.size());
        std::uint32_t s = seq + static_cast<std::uint32_t>(part.first);
        out.push_back(make_segment(pkt, pl + part.first, part.second, s, flags, -1,
                                   reverse_tail && cfg.fooling_badseq));
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
        out.push_back(make_segment(pkt, fake.data(), fake.size(), seq, flags, cfg.fake_ttl, false));
        out.push_back(make_segment(pkt, pl, plen, seq, flags, -1, false));
        break;
    }

    case Strategy::FakeMultidisorder:
    case Strategy::FakeAuto: {
        std::vector<std::uint8_t> fake = build_fake_payload(pl, plen, tls, cfg);
        out.push_back(make_segment(pkt, fake.data(), fake.size(), seq, flags, cfg.fake_ttl, false));

        std::vector<Packet> core = do_multidisorder(pkt, pl, plen, seq, flags, split, cfg);
        out.insert(out.end(), core.begin(), core.end());
        break;
    }
    }

    return emit_with_repeats(out, cfg.repeats);
}

}
