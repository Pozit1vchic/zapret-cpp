#include "tls.hpp"

namespace zc {

static std::uint16_t rd16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

TlsClientHello parse_client_hello(const std::uint8_t* p, std::size_t n) {
    TlsClientHello out;
    if (n < 9) {
        return out;
    }
    if (p[0] != 0x16) {
        return out;
    }

    std::size_t record_end = 5 + static_cast<std::size_t>(rd16(p + 3));
    if (record_end > n) {
        record_end = n;
    }

    std::size_t o = 5;
    if (p[o] != 0x01) {
        return out;
    }
    o += 4;

    if (o + 34 > record_end) {
        return out;
    }
    o += 34;

    if (o + 1 > record_end) {
        return out;
    }
    o += 1 + static_cast<std::size_t>(p[o]);

    if (o + 2 > record_end) {
        return out;
    }
    o += 2 + static_cast<std::size_t>(rd16(p + o));

    if (o + 1 > record_end) {
        return out;
    }
    o += 1 + static_cast<std::size_t>(p[o]);

    if (o + 2 > record_end) {
        return out;
    }
    std::size_t ext_end = o + 2 + static_cast<std::size_t>(rd16(p + o));
    o += 2;
    if (ext_end > record_end) {
        ext_end = record_end;
    }

    while (o + 4 <= ext_end) {
        std::uint16_t type = rd16(p + o);
        std::uint16_t elen = rd16(p + o + 2);
        o += 4;
        if (o + elen > ext_end) {
            break;
        }

        if (type == 0x0000 && elen >= 2) {
            std::size_t q = o + 2;
            std::size_t q_end = o + elen;
            while (q + 3 <= q_end) {
                std::uint8_t  ntype = p[q];
                std::uint16_t nlen = rd16(p + q + 1);
                q += 3;
                if (q + nlen > q_end) {
                    break;
                }
                if (ntype == 0x00) {
                    out.valid = true;
                    out.sni_offset = q;
                    out.sni_length = nlen;
                    out.list_length = rd16(p + o);
                    return out;
                }
                q += nlen;
            }
        }

        o += elen;
    }

    return out;
}

}
