#include "quic.hpp"

#include <chrono>

namespace zc {

namespace {

std::uint8_t rnd_byte() {
    static std::uint32_t state = [] {
        auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        return 0x9e3779b9u ^ static_cast<std::uint32_t>(now);
    }();
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return static_cast<std::uint8_t>(state & 0xff);
}

std::uint32_t rd32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

}

QuicInitial parse_quic_initial(const std::uint8_t* p, std::size_t n) {
    QuicInitial out;

    if (n < 7) {
        return out;
    }

    if ((p[0] & 0x80) == 0) {
        return out;
    }

    std::uint8_t type = static_cast<std::uint8_t>((p[0] >> 4) & 0x03);
    if (type != 0x00) {
        return out;
    }

    std::uint32_t version = rd32(p + 1);
    if (version == 0) {
        return out;
    }

    out.header_offset = 0;
    out.version_first = p[1];

    std::size_t o = 5;

    if (o + 1 > n) {
        return out;
    }
    std::size_t dcid_len = p[o++];
    if (dcid_len > 20 || o + dcid_len > n) {
        return out;
    }
    out.dcid_offset = o;
    out.dcid_length = dcid_len;
    o += dcid_len;

    if (o + 1 > n) {
        return out;
    }
    std::size_t scid_len = p[o++];
    if (scid_len > 20 || o + scid_len > n) {
        return out;
    }
    out.scid_offset = o;
    out.scid_length = scid_len;
    o += scid_len;

    if (o + 1 > n) {
        return out;
    }
    std::size_t token_len = p[o++];
    if (o + token_len > n) {
        return out;
    }
    out.token_offset = o;
    out.token_length = token_len;
    o += token_len;

    if (o + 2 > n) {
        return out;
    }
    out.length = (static_cast<std::uint32_t>(p[o]) << 8) |
                 static_cast<std::uint32_t>(p[o + 1]);

    out.valid = true;
    return out;
}

std::vector<std::uint8_t> build_fake_quic_initial(std::size_t target_size,
                                                  const QuicInitial* real) {
    if (target_size < 40) {
        target_size = 40;
    }

    std::vector<std::uint8_t> out;
    out.reserve(target_size);

    out.push_back(0xc0);

    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x01);

    std::size_t dcid_len = 8;
    if (real && real->valid && real->dcid_length > 0) {
        dcid_len = real->dcid_length;
    }
    out.push_back(static_cast<std::uint8_t>(dcid_len));
    for (std::size_t i = 0; i < dcid_len; ++i) {
        out.push_back(rnd_byte());
    }

    std::size_t scid_len = 0;
    out.push_back(static_cast<std::uint8_t>(scid_len));

    out.push_back(0x00);

    std::size_t body_target = (target_size > out.size() + 2) ? target_size - out.size() - 2 : 32;
    out.push_back(static_cast<std::uint8_t>((body_target >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(body_target & 0xff));

    while (out.size() < target_size) {
        out.push_back(rnd_byte());
    }

    return out;
}

}
