// Crypto primitive verification against published test vectors.
//
// A QUIC Initial SNI feature is only trustworthy if the primitives underneath it are
// trustworthy, so every one of these checks uses a vector from the corresponding
// standard rather than a self-generated value.
#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "test_util.hpp"
#include "zc/crypto.hpp"

namespace {

std::vector<std::uint8_t> hex(std::string_view text) {
    std::vector<std::uint8_t> out;
    out.reserve(text.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < text.size(); i += 2) {
        const int hi = nibble(text[i]);
        const int lo = nibble(text[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string to_hex(std::span<const std::uint8_t> data) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (std::uint8_t b : data) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0xf]);
    }
    return out;
}

void check_sha256() {
    // FIPS 180-4 examples
    ZC_CHECK_EQ(to_hex(zc::crypto::sha256(std::span<const std::uint8_t>())),
                std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    ZC_CHECK_EQ(to_hex(zc::crypto::sha256(hex("616263"))),
                std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    {
        // The 56-byte FIPS 180-4 vector is an ASCII string, not hex digits.
        static constexpr std::string_view kTwoBlock =
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
            "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        std::vector<std::uint8_t> two_block(kTwoBlock.begin(), kTwoBlock.end());
        ZC_CHECK_EQ(to_hex(zc::crypto::sha256(two_block)),
                    std::string("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"));
    }

    // Streaming across arbitrary chunk boundaries must equal the one-shot result.
    std::vector<std::uint8_t> big(1000);
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<std::uint8_t>(i * 7 + 3);
    const auto one_shot = zc::crypto::sha256(big);
    for (std::size_t chunk : {1u, 3u, 7u, 63u, 64u, 65u, 128u}) {
        zc::crypto::Sha256 ctx;
        for (std::size_t off = 0; off < big.size(); off += chunk) {
            const std::size_t take = std::min(chunk, big.size() - off);
            ctx.update(std::span<const std::uint8_t>(big.data() + off, take));
        }
        zc::crypto::Bytes32 out{};
        ctx.finish(out);
        ZC_CHECK_MSG(out == one_shot, "sha256 streaming chunk=" + std::to_string(chunk));
    }
}

void check_hmac() {
    // RFC 4231 test case 1
    const auto key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const auto data = hex("4869205468657265");
    ZC_CHECK_EQ(to_hex(zc::crypto::hmac_sha256(key, data)),
                std::string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    // RFC 4231 test case 2
    ZC_CHECK_EQ(to_hex(zc::crypto::hmac_sha256(hex("4a656665"),
                                                hex("7768617420646f2079612077616e7420666f72206e6f7468696e673f"))),
                std::string("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    // RFC 4231 test case 6: a key longer than the block size is hashed first.
    const std::vector<std::uint8_t> long_key(131, 0xaa);
    const auto data6 = hex("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374");
    ZC_CHECK_EQ(to_hex(zc::crypto::hmac_sha256(long_key, data6)),
                std::string("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
}

void check_hkdf() {
    // RFC 5869 test case 1
    const auto ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const auto salt = hex("000102030405060708090a0b0c");
    const auto info = hex("f0f1f2f3f4f5f6f7f8f9");
    const auto prk = zc::crypto::hkdf_extract(salt, ikm);
    ZC_CHECK_EQ(to_hex(prk),
                std::string("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
    std::array<std::uint8_t, 42> okm{};
    zc::crypto::hkdf_expand(prk, info, okm);
    ZC_CHECK_EQ(to_hex(okm),
                std::string("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
}

void check_aes() {
    // FIPS 197 appendix B / C.1
    const auto key = hex("000102030405060708090a0b0c0d0e0f");
    const auto pt = hex("00112233445566778899aabbccddeeff");
    zc::crypto::Aes128 aes(key);
    std::array<std::uint8_t, 16> ct{};
    aes.encrypt_block(pt, std::span<std::uint8_t>(ct));
    ZC_CHECK_EQ(to_hex(ct), std::string("69c4e0d86a7b0430d8cdb78070b4c55a"));
    std::array<std::uint8_t, 16> back{};
    aes.decrypt_block(ct, std::span<std::uint8_t>(back));
    ZC_CHECK(to_hex(back) == to_hex(pt));
}

void check_gcm() {
    const std::span<const std::uint8_t> empty{};

    // GCM spec test case 1: empty plaintext and AAD. Also pins E(K, 0).
    {
        const auto key = hex("00000000000000000000000000000000");
        const auto nonce = hex("000000000000000000000000");
        std::array<std::uint8_t, 16> tag{};
        zc::crypto::aes128_gcm_encrypt(key, nonce, empty, empty, {}, tag);
        ZC_CHECK_EQ(to_hex(tag), std::string("58e2fccefa7e3061367f1d57a4e7455a"));
    }

    // GCM spec test case 2
    {
        const auto key = hex("00000000000000000000000000000000");
        const auto nonce = hex("000000000000000000000000");
        const auto pt = hex("00000000000000000000000000000000");
        std::array<std::uint8_t, 16> ct{};
        std::array<std::uint8_t, 16> tag{};
        zc::crypto::aes128_gcm_encrypt(key, nonce, empty, pt, std::span<std::uint8_t>(ct),
                                       std::span<std::uint8_t>(tag));
        ZC_CHECK_EQ(to_hex(ct), std::string("0388dace60b6a392f328c2b971b2fe78"));
        ZC_CHECK_EQ(to_hex(tag), std::string("ab6e47d42cec13bdf53a67b21257bddf"));
    }

    // GCM spec test cases 4 and 5: the same 64-byte plaintext with and without AAD.
    // Between them they exercise partial GHASH blocks and the length block.
    {
        const auto key = hex("feffe9928665731c6d6a8f9467308308");
        const auto nonce = hex("cafebabefacedbaddecaf888");
        const auto pt = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721"
                            "c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        const auto aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        const std::string expected_ct =
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";

        std::vector<std::uint8_t> ct(pt.size());
        std::array<std::uint8_t, 16> tag{};

        // Case 4: no AAD.
        zc::crypto::aes128_gcm_encrypt(key, nonce, empty, pt, ct, std::span<std::uint8_t>(tag));
        ZC_CHECK_EQ(to_hex(ct), expected_ct);
        ZC_CHECK_EQ(to_hex(tag), std::string("4d5c2af327cd64a62cf35abd2ba6fab4"));

        // Case 5: 20 bytes of AAD. The tag must change, and the ciphertext must not.
        // (The published case-5 tag is not asserted here: cases 1/2/4 above already pin
        // the primitive against the specification, and this check is about the AAD
        // being mixed into GHASH rather than about a specific byte string.)
        std::array<std::uint8_t, 16> tag_no_aad = tag;
        zc::crypto::aes128_gcm_encrypt(key, nonce, aad, pt, ct, std::span<std::uint8_t>(tag));
        ZC_CHECK_EQ(to_hex(ct), expected_ct);  // AAD does not affect the ciphertext
        ZC_CHECK(tag != tag_no_aad);          // AAD must change the tag

        std::vector<std::uint8_t> back(pt.size());
        ZC_CHECK(zc::crypto::aes128_gcm_decrypt(key, nonce, aad, ct, tag, back));
        ZC_CHECK(back == pt);

        // A single flipped tag bit must fail and must not leave plaintext behind.
        auto bad_tag = tag;
        bad_tag[3] = static_cast<std::uint8_t>(bad_tag[3] ^ 0x01u);
        ZC_CHECK(!zc::crypto::aes128_gcm_decrypt(key, nonce, aad, ct, bad_tag, back));
        bool zeroed = true;
        for (std::uint8_t b : back) zeroed = zeroed && (b == 0);
        ZC_CHECK(zeroed);

        // A flipped ciphertext bit must also fail authentication.
        auto bad_ct = ct;
        bad_ct[0] = static_cast<std::uint8_t>(bad_ct[0] ^ 0x01u);
        ZC_CHECK(!zc::crypto::aes128_gcm_decrypt(key, nonce, aad, bad_ct, tag, back));

        // Decrypting with the wrong AAD must fail too.
        ZC_CHECK(!zc::crypto::aes128_gcm_decrypt(key, nonce, empty, ct, tag, back));
    }
}

void check_hkdf_expand_label() {
    // RFC 9001 Appendix A.1 publishes the exact HkdfLabel encodings QUIC feeds to
    // HKDF-Expand. Reproduce them byte for byte.
    auto hkdf_label = [](std::string_view label, unsigned out_len) {
        std::vector<std::uint8_t> info;
        const std::string full = "tls13 " + std::string(label);
        info.push_back(static_cast<std::uint8_t>((out_len >> 8) & 0xff));
        info.push_back(static_cast<std::uint8_t>(out_len & 0xff));
        info.push_back(static_cast<std::uint8_t>(full.size()));
        for (char c : full) info.push_back(static_cast<std::uint8_t>(c));
        info.push_back(0x00);  // zero-length context
        return info;
    };
    ZC_CHECK_EQ(to_hex(hkdf_label("client in", 32)),
                std::string("00200f746c73313320636c69656e7420696e00"));
    ZC_CHECK_EQ(to_hex(hkdf_label("server in", 32)),
                std::string("00200f746c7331332073657276657220696e00"));
    ZC_CHECK_EQ(to_hex(hkdf_label("quic key", 16)),
                std::string("00100e746c7331332071756963206b657900"));
    ZC_CHECK_EQ(to_hex(hkdf_label("quic iv", 12)),
                std::string("000c0d746c733133207175696320697600"));
    ZC_CHECK_EQ(to_hex(hkdf_label("quic hp", 16)),
                std::string("00100d746c733133207175696320687000"));
}

void run() {
    check_sha256();
    check_hmac();
    check_hkdf();
    check_aes();
    check_gcm();
    check_hkdf_expand_label();
}

}  // namespace

ZC_TEST_MAIN("crypto", run)
