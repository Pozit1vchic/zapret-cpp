#include "zc/crypto.hpp"

#include <algorithm>
#include <cstring>

namespace zc::crypto {
namespace {

// --- small endian helpers ----------------------------------------------------
std::uint32_t load_be32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}
void store_be32(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

constexpr std::uint32_t rotr(std::uint32_t x, unsigned n) noexcept {
    return (x >> n) | (x << (32u - n));
}

constexpr std::uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

constexpr std::uint8_t rsbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d};

constexpr std::uint8_t rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

constexpr std::uint8_t gf_mul(std::uint8_t a, std::uint8_t b) noexcept {
    std::uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if ((b & 1u) != 0) p = static_cast<std::uint8_t>(p ^ a);
        const bool hi = (a & 0x80u) != 0;
        a = static_cast<std::uint8_t>(a << 1);
        if (hi) a = static_cast<std::uint8_t>(a ^ 0x1bu);
        b = static_cast<std::uint8_t>(b >> 1);
    }
    return p;
}

void expand_key(std::span<const std::uint8_t> key, std::uint32_t* rk) noexcept {
    std::uint8_t w[176] = {};
    std::memcpy(w, key.data(), 16);
    for (std::size_t i = 16; i < 176; i += 4) {
        std::uint8_t t[4] = {w[i - 4], w[i - 3], w[i - 2], w[i - 1]};
        if ((i % 16) == 0) {
            const std::uint8_t tmp = t[0];
            t[0] = static_cast<std::uint8_t>(sbox[t[1]] ^ rcon[i / 16]);
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[tmp];
        }
        for (int j = 0; j < 4; ++j) {
            w[i + static_cast<std::size_t>(j)] =
                static_cast<std::uint8_t>(w[i - 16 + static_cast<std::size_t>(j)] ^ t[j]);
        }
    }
    for (std::size_t i = 0; i < 44; ++i) {
        rk[i] = (static_cast<std::uint32_t>(w[i * 4]) << 24) |
                (static_cast<std::uint32_t>(w[i * 4 + 1]) << 16) |
                (static_cast<std::uint32_t>(w[i * 4 + 2]) << 8) |
                static_cast<std::uint32_t>(w[i * 4 + 3]);
    }
}

void add_round_key(std::uint8_t s[16], const std::uint32_t* rk) noexcept {
    for (int c = 0; c < 4; ++c) {
        s[c * 4] = static_cast<std::uint8_t>(s[c * 4] ^ (rk[c] >> 24));
        s[c * 4 + 1] = static_cast<std::uint8_t>(s[c * 4 + 1] ^ (rk[c] >> 16));
        s[c * 4 + 2] = static_cast<std::uint8_t>(s[c * 4 + 2] ^ (rk[c] >> 8));
        s[c * 4 + 3] = static_cast<std::uint8_t>(s[c * 4 + 3] ^ rk[c]);
    }
}

void aes_encrypt_core(const std::uint32_t* rk, std::uint8_t s[16]) noexcept {
    add_round_key(s, rk);
    for (int round = 1; round <= 10; ++round) {
        for (int i = 0; i < 16; ++i) s[i] = sbox[s[i]];
        std::uint8_t t[16];
        for (int c = 0; c < 4; ++c) {
            for (int r = 0; r < 4; ++r) {
                t[c * 4 + r] = s[((c + r) & 3) * 4 + r];
            }
        }
        std::memcpy(s, t, 16);
        if (round != 10) {
            for (int c = 0; c < 4; ++c) {
                std::uint8_t* col = s + c * 4;
                const std::uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                col[0] = static_cast<std::uint8_t>(gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3);
                col[1] = static_cast<std::uint8_t>(a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3);
                col[2] = static_cast<std::uint8_t>(a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3));
                col[3] = static_cast<std::uint8_t>(gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2));
            }
        }
        add_round_key(s, rk + round * 4);
    }
}

void aes_decrypt_core(const std::uint32_t* rk, std::uint8_t s[16]) noexcept {
    add_round_key(s, rk + 40);
    for (int round = 9; round >= 0; --round) {
        std::uint8_t t[16];
        for (int c = 0; c < 4; ++c) {
            for (int r = 0; r < 4; ++r) {
                t[((c + r) & 3) * 4 + r] = s[c * 4 + r];
            }
        }
        std::memcpy(s, t, 16);
        for (int i = 0; i < 16; ++i) s[i] = rsbox[s[i]];
        add_round_key(s, rk + round * 4);
        if (round != 0) {
            for (int c = 0; c < 4; ++c) {
                std::uint8_t* col = s + c * 4;
                const std::uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                col[0] = static_cast<std::uint8_t>(gf_mul(a0, 14) ^ gf_mul(a1, 11) ^
                                                    gf_mul(a2, 13) ^ gf_mul(a3, 9));
                col[1] = static_cast<std::uint8_t>(gf_mul(a0, 9) ^ gf_mul(a1, 14) ^
                                                    gf_mul(a2, 11) ^ gf_mul(a3, 13));
                col[2] = static_cast<std::uint8_t>(gf_mul(a0, 13) ^ gf_mul(a1, 9) ^
                                                    gf_mul(a2, 14) ^ gf_mul(a3, 11));
                col[3] = static_cast<std::uint8_t>(gf_mul(a0, 11) ^ gf_mul(a1, 13) ^
                                                    gf_mul(a2, 9) ^ gf_mul(a3, 14));
            }
        }
    }
}

void gcm_ctr(const Aes128& aes, const std::uint8_t counter0[16],
             std::span<const std::uint8_t> in, std::span<std::uint8_t> out) noexcept {
    std::uint8_t counter[16];
    std::memcpy(counter, counter0, 16);
    std::uint8_t stream[16];
    std::uint32_t c = load_be32(counter + 12);
    std::size_t off = 0;
    while (off < in.size()) {
        store_be32(counter + 12, ++c);
        aes.encrypt_block(std::span<const std::uint8_t>(counter, 16),
                          std::span<std::uint8_t>(stream, 16));
        const std::size_t chunk = std::min<std::size_t>(16, in.size() - off);
        for (std::size_t i = 0; i < chunk; ++i) out[off + i] = in[off + i] ^ stream[i];
        off += chunk;
    }
    std::memset(stream, 0, sizeof(stream));
}

}  // namespace

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

void Sha256::reset() noexcept {
    h_[0] = 0x6a09e667u; h_[1] = 0xbb67ae85u; h_[2] = 0x3c6ef372u; h_[3] = 0xa54ff53au;
    h_[4] = 0x510e527fu; h_[5] = 0x9b05688cu; h_[6] = 0x1f83d9abu; h_[7] = 0x5be0cd19u;
    buffered_ = 0;
    total_bits_ = 0;
    std::memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::compress(const std::uint8_t block[64]) noexcept {
    std::uint32_t w[64];
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
               static_cast<std::uint32_t>(block[i * 4 + 3]);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    std::uint32_t e = h_[4], f = h_[5], g = h_[6], hh = h_[7];
    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t t1 = hh + S1 + ch + kSha256K[i] + w[i];
        const std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
    h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += hh;
}

void Sha256::update(std::span<const std::uint8_t> data) noexcept {
    total_bits_ += static_cast<std::uint64_t>(data.size()) * 8u;
    std::size_t off = 0;
    if (buffered_ > 0) {
        const std::size_t take = std::min<std::size_t>(64 - buffered_, data.size());
        std::memcpy(buffer_ + buffered_, data.data(), take);
        buffered_ += take;
        off += take;
        if (buffered_ == 64) {
            compress(buffer_);
            buffered_ = 0;
        }
    }
    while (off + 64 <= data.size()) {
        compress(data.data() + off);
        off += 64;
    }
    if (off < data.size()) {
        std::memcpy(buffer_, data.data() + off, data.size() - off);
        buffered_ = data.size() - off;
    }
}

void Sha256::finish(Bytes32& out) noexcept {
    const std::uint64_t bits = total_bits_;
    std::uint8_t pad[64] = {};
    pad[0] = 0x80;
    const std::size_t pad_len = (buffered_ < 56) ? (56 - buffered_) : (120 - buffered_);
    total_bits_ = bits;  // update() below would otherwise inflate it
    update(std::span<const std::uint8_t>(pad, pad_len));
    std::uint8_t len_be[8];
    store_be32(len_be, static_cast<std::uint32_t>(bits >> 32));
    store_be32(len_be + 4, static_cast<std::uint32_t>(bits & 0xffffffffu));
    update(std::span<const std::uint8_t>(len_be, 8));
    for (std::size_t i = 0; i < 8; ++i) {
        out[i * 4] = static_cast<std::uint8_t>(h_[i] >> 24);
        out[i * 4 + 1] = static_cast<std::uint8_t>(h_[i] >> 16);
        out[i * 4 + 2] = static_cast<std::uint8_t>(h_[i] >> 8);
        out[i * 4 + 3] = static_cast<std::uint8_t>(h_[i]);
    }
    std::memset(buffer_, 0, sizeof(buffer_));
    buffered_ = 0;
}

Bytes32 sha256(std::span<const std::uint8_t> data) noexcept {
    Sha256 ctx;
    ctx.update(data);
    Bytes32 out{};
    ctx.finish(out);
    return out;
}

Bytes32 hmac_sha256(std::span<const std::uint8_t> key,
                    std::span<const std::uint8_t> data) noexcept {
    std::uint8_t k[64] = {};
    if (key.size() > 64) {
        const Bytes32 h = sha256(key);
        std::memcpy(k, h.data(), 32);
    } else if (!key.empty()) {
        std::memcpy(k, key.data(), key.size());
    }
    std::uint8_t ipad[64];
    std::uint8_t opad[64];
    for (std::size_t i = 0; i < 64; ++i) {
        ipad[i] = static_cast<std::uint8_t>(k[i] ^ 0x36u);
        opad[i] = static_cast<std::uint8_t>(k[i] ^ 0x5cu);
    }
    Bytes32 inner{};
    {
        Sha256 ctx;
        ctx.update(std::span<const std::uint8_t>(ipad, 64));
        ctx.update(data);
        ctx.finish(inner);
    }
    Sha256 ctx;
    ctx.update(std::span<const std::uint8_t>(opad, 64));
    ctx.update(std::span<const std::uint8_t>(inner.data(), 32));
    Bytes32 out{};
    ctx.finish(out);
    std::memset(k, 0, sizeof(k));
    std::memset(ipad, 0, sizeof(ipad));
    std::memset(opad, 0, sizeof(opad));
    return out;
}

Bytes32 hkdf_extract(std::span<const std::uint8_t> salt,
                     std::span<const std::uint8_t> ikm) noexcept {
    static constexpr std::array<std::uint8_t, 32> zeros{};
    return hmac_sha256(salt.empty() ? std::span<const std::uint8_t>(zeros) : salt, ikm);
}

void hkdf_expand(std::span<const std::uint8_t> prk, std::span<const std::uint8_t> info,
                 std::span<std::uint8_t> out) noexcept {
    std::uint8_t t[32] = {};
    std::size_t t_len = 0;
    std::size_t done = 0;
    unsigned counter = 1;
    while (done < out.size() && counter <= 255) {
        std::array<std::uint8_t, 32 + 255 + 1> input{};
        std::size_t input_len = 0;
        if (t_len > 0) {
            std::memcpy(input.data(), t, t_len);
            input_len = t_len;
        }
        const std::size_t info_len = std::min<std::size_t>(info.size(), 255);
        if (info_len > 0) {
            std::memcpy(input.data() + input_len, info.data(), info_len);
            input_len += info_len;
        }
        input[input_len++] = static_cast<std::uint8_t>(counter);
        const Bytes32 block =
            hmac_sha256(prk, std::span<const std::uint8_t>(input.data(), input_len));
        std::memcpy(t, block.data(), 32);
        t_len = 32;
        const std::size_t take = std::min<std::size_t>(32, out.size() - done);
        std::memcpy(out.data() + done, t, take);
        done += take;
        ++counter;
    }
    std::memset(t, 0, sizeof(t));
}

void hkdf_expand_label(std::span<const std::uint8_t> secret, std::string_view label,
                       std::span<const std::uint8_t> context, std::span<std::uint8_t> out) {
    static constexpr std::string_view kPrefix = "tls13 ";
    const std::string_view bounded =
        label.size() > 200 ? label.substr(0, 200) : label;  // keep the length byte sane
    std::array<std::uint8_t, 2 + 1 + 255 + 1 + 255> info{};
    std::size_t p = 0;
    info[p++] = static_cast<std::uint8_t>((out.size() >> 8) & 0xffu);
    info[p++] = static_cast<std::uint8_t>(out.size() & 0xffu);
    info[p++] = static_cast<std::uint8_t>(kPrefix.size() + bounded.size());
    std::memcpy(info.data() + p, kPrefix.data(), kPrefix.size());
    p += kPrefix.size();
    std::memcpy(info.data() + p, bounded.data(), bounded.size());
    p += bounded.size();
    const std::size_t ctx_len = std::min<std::size_t>(context.size(), 255);
    info[p++] = static_cast<std::uint8_t>(ctx_len);
    if (ctx_len > 0) {
        std::memcpy(info.data() + p, context.data(), ctx_len);
        p += ctx_len;
    }
    hkdf_expand(secret, std::span<const std::uint8_t>(info.data(), p), out);
}

Bytes32 hkdf_expand_label_value(std::span<const std::uint8_t> secret,
                                std::string_view label) noexcept {
    Bytes32 out{};
    hkdf_expand_label(secret, label, {}, std::span<std::uint8_t>(out));
    return out;
}

// ---------------------------------------------------------------------------
// AES-128 (FIPS 197) and AES-128-GCM (SP 800-38D)
// ---------------------------------------------------------------------------

Aes128::Aes128(std::span<const std::uint8_t> key) noexcept {
    std::array<std::uint8_t, 16> k{};
    if (key.size() >= 16) {
        std::memcpy(k.data(), key.data(), 16);
    } else if (!key.empty()) {
        std::memcpy(k.data(), key.data(), key.size());
    }
    expand_key(std::span<const std::uint8_t>(k.data(), 16), round_keys_);
}

void Aes128::encrypt_block(std::span<const std::uint8_t> in,
                       std::span<std::uint8_t> out) const noexcept {
    std::uint8_t s[16];
    std::memcpy(s, in.data(), 16);
    aes_encrypt_core(round_keys_, s);
    std::memcpy(out.data(), s, 16);
}

void Aes128::decrypt_block(std::span<const std::uint8_t> in,
                       std::span<std::uint8_t> out) const noexcept {
    std::uint8_t s[16];
    std::memcpy(s, in.data(), 16);
    aes_decrypt_core(round_keys_, s);
    std::memcpy(out.data(), s, 16);
}

void ghash_mul(std::span<std::uint8_t> x, std::span<const std::uint8_t> h) noexcept {
    std::uint8_t z[16] = {};
    std::uint8_t v[16];
    std::memcpy(v, h.data(), 16);
    // GHASH is a GF(2^128) multiplication with the reversed-bit convention of
    // SP 800-38D: V is right-shifted once per *bit*, not once per byte.
    for (std::size_t i = 0; i < 16; ++i) {
        for (int bit = 7; bit >= 0; --bit) {
            if (((x[i] >> bit) & 1u) != 0) {
                for (std::size_t j = 0; j < 16; ++j) z[j] = static_cast<std::uint8_t>(z[j] ^ v[j]);
            }
            const bool lsb = (v[15] & 1u) != 0;
            for (std::size_t j = 15; j > 0; --j) {
                v[j] = static_cast<std::uint8_t>((v[j] >> 1) | (v[j - 1] << 7));
            }
            v[0] = static_cast<std::uint8_t>(v[0] >> 1);
            if (lsb) v[0] = static_cast<std::uint8_t>(v[0] ^ 0xe1u);
        }
    }
    std::memcpy(x.data(), z, 16);
    std::memset(z, 0, sizeof(z));
    std::memset(v, 0, sizeof(v));
}

namespace {

void ghash_update(std::uint8_t y[16], std::span<const std::uint8_t> data,
                  const std::uint8_t h[16]) noexcept {
    std::size_t off = 0;
    while (off < data.size()) {
        const std::size_t chunk = std::min<std::size_t>(16, data.size() - off);
        // GHASH blocks are exactly 16 bytes; a short trailing block is zero padded.
        // The accumulator must be cleared past `chunk` first, otherwise stale bytes
        // from earlier blocks leak into the final multiplication.
        for (std::size_t i = chunk; i < 16; ++i) y[i] = 0;
        for (std::size_t i = 0; i < chunk; ++i) y[i] = static_cast<std::uint8_t>(y[i] ^ data[off + i]);
        ghash_mul(std::span<std::uint8_t>(y, 16), std::span<const std::uint8_t>(h, 16));
        off += chunk;
    }
}

// Runs the GCM keystream over `input` into `out` and computes the authentication tag
// over `aad` and the ciphertext. `encrypt` selects whether `out` (ciphertext) or
// `input` (ciphertext, when decrypting) is the value that gets authenticated.
void gcm_core(std::span<const std::uint8_t> key, const std::uint8_t nonce[12],
              std::span<const std::uint8_t> aad, std::span<const std::uint8_t> input,
              std::span<std::uint8_t> out, bool encrypt, std::uint8_t tag[16]) noexcept {
    const Aes128 aes(key);
    static constexpr std::uint8_t kZeroBlock[16] = {};
    std::uint8_t h[16] = {};
    aes.encrypt_block(std::span<const std::uint8_t>(kZeroBlock, 16),
                      std::span<std::uint8_t>(h, 16));

    std::uint8_t counter0[16] = {};
    std::memcpy(counter0, nonce, 12);
    counter0[15] = 1;  // J0 = IV || 0x00000001 for a 96-bit IV

    if (!input.empty() && out.size() >= input.size()) {
        gcm_ctr(aes, counter0, input, out.first(input.size()));
    }

    // GHASH always covers the ciphertext, never the plaintext.
    const std::span<const std::uint8_t> ciphertext =
        encrypt ? std::span<const std::uint8_t>(out.data(), input.size()) : input;

    std::uint8_t y[16] = {};
    if (!aad.empty()) ghash_update(y, aad, h);
    if (!ciphertext.empty()) ghash_update(y, ciphertext, h);
    // GHASH length block: 64-bit big-endian bit length of AAD followed by that of the
    // ciphertext (SP 800-38D section 7.1).
    std::uint8_t lengths[16] = {};
    const std::uint64_t aad_bits = static_cast<std::uint64_t>(aad.size()) * 8u;
    const std::uint64_t ct_bits = static_cast<std::uint64_t>(ciphertext.size()) * 8u;
    store_be32(lengths + 0, static_cast<std::uint32_t>(aad_bits >> 32));
    store_be32(lengths + 4, static_cast<std::uint32_t>(aad_bits & 0xffffffffu));
    store_be32(lengths + 8, static_cast<std::uint32_t>(ct_bits >> 32));
    store_be32(lengths + 12, static_cast<std::uint32_t>(ct_bits & 0xffffffffu));
    ghash_update(y, std::span<const std::uint8_t>(lengths, 16), h);

    std::uint8_t s[16];
    aes.encrypt_block(std::span<const std::uint8_t>(counter0, 16),
                      std::span<std::uint8_t>(s, 16));
    for (std::size_t i = 0; i < 16; ++i) tag[i] = static_cast<std::uint8_t>(y[i] ^ s[i]);
    std::memset(s, 0, sizeof(s));
    std::memset(y, 0, sizeof(y));
    std::memset(h, 0, sizeof(h));
}

}  // namespace

void aes128_gcm_encrypt(std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
                        std::span<const std::uint8_t> aad,
                        std::span<const std::uint8_t> plaintext,
                        std::span<std::uint8_t> ciphertext, std::span<std::uint8_t> tag) noexcept {
    gcm_core(key, nonce.data(), aad, plaintext, ciphertext, true, tag.data());
}

bool aes128_gcm_decrypt(std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
                        std::span<const std::uint8_t> aad,
                        std::span<const std::uint8_t> ciphertext,
                        std::span<const std::uint8_t> tag,
                        std::span<std::uint8_t> plaintext) noexcept {
    std::array<std::uint8_t, 16> expected{};
    gcm_core(key, nonce.data(), aad, ciphertext, plaintext, false, expected.data());
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < 16; ++i) {
        diff = static_cast<std::uint8_t>(diff | (expected[i] ^ tag[i]));
    }
    if (diff != 0) {
        if (!plaintext.empty()) std::memset(plaintext.data(), 0, plaintext.size());
        return false;
    }
    return true;
}

}  // namespace zc::crypto
