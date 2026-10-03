// QUIC verification against RFC 9001 Appendix A.
//
// The RFC publishes a complete client Initial packet for QUIC v1 together with every
// intermediate value: the Destination Connection ID, the derived secrets and keys, the
// header-protection sample and mask, the protected and unprotected headers, and the
// unprotected CRYPTO frame payload.
//
// That allows a much stronger test than "does my parser round-trip with itself":
//   1. derive the keys and compare with A.1;
//   2. recompute the header-protection mask from the published sample and compare with
//      the published mask, then reproduce the published protected header;
//   3. re-encrypt the published unprotected payload and compare all 1162 published
//      ciphertext bytes byte for byte;
//   4. decrypt the published packet, reassemble CRYPTO, and read the SNI;
//   5. tamper with single bits and confirm authentication rejects it.
//
// Byte-exact agreement with the IETF's own bytes is what makes "we can read QUIC
// hostnames" a verified claim rather than a hopeful one.
#include <algorithm>
#include <array>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "rfc9001_vectors.h"
#include "test_util.hpp"
#include "zc/crypto.hpp"
#include "zc/quic.hpp"
#include "zc/tls.hpp"

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

std::string to_hex(std::span<const std::uint8_t> d) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(d.size() * 2);
    for (std::uint8_t b : d) {
        s.push_back(digits[b >> 4]);
        s.push_back(digits[b & 0xf]);
    }
    return s;
}

void check_key_derivation() {
    using namespace zctest::rfc9001;
    const auto dcid = hex(kDcid);
    ZC_REQUIRE(dcid.size() == 8);

    // RFC 9001 Appendix A.1 lists the HKDF labels and the resulting secrets.
    const zc::crypto::Bytes32 salt = zc::crypto::hkdf_extract(
        hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), dcid);
    ZC_CHECK_EQ(to_hex(salt), std::string(kInitialSecret));

    const zc::crypto::Bytes32 client_secret =
        zc::crypto::hkdf_expand_label_value(salt, "client in");
    ZC_CHECK_EQ(to_hex(client_secret), std::string(kClientInitialSecret));

    const auto keys = zc::quic_initial_keys(0x00000001u, dcid);
    ZC_REQUIRE(keys.has_value());
    ZC_CHECK_EQ(to_hex(keys->key), std::string(kClientKey));
    ZC_CHECK_EQ(to_hex(keys->iv), std::string(kClientIv));
    ZC_CHECK_EQ(to_hex(keys->hp), std::string(kClientHp));

    // QUIC v2 must not silently reuse the v1 salt or labels (RFC 9369 3.3).
    const auto v2 = zc::quic_initial_keys(0x6b3343cfu, dcid);
    ZC_REQUIRE(v2.has_value());
    ZC_CHECK(v2->key != keys->key);
    ZC_CHECK(v2->iv != keys->iv);
    ZC_CHECK(v2->hp != keys->hp);

    // Unknown versions are refused rather than approximated.
    ZC_CHECK(!zc::quic_initial_keys(0x11223344u, dcid).has_value());
    ZC_CHECK(!zc::quic_initial_keys(0x00000000u, dcid).has_value());
    // An over-long connection ID is refused (RFC 9000 caps it at 20).
    ZC_CHECK(!zc::quic_initial_keys(0x00000001u, std::array<std::uint8_t, 21>{}).has_value());
}

void check_header_protection() {
    using namespace zctest::rfc9001;
    const auto keys = zc::quic_initial_keys(0x00000001u, hex(kDcid));
    ZC_REQUIRE(keys.has_value());

    // RFC 9001 5.4.3: mask = AES-ECB(hp, sample).
    const auto sample = hex(kSample);
    const zc::crypto::Aes128 hp(keys->hp);
    std::array<std::uint8_t, 16> mask{};
    hp.encrypt_block(sample, std::span<std::uint8_t>(mask));
    ZC_CHECK_EQ(to_hex(std::span<const std::uint8_t>(mask).first(5)), std::string(kMask));

    // Reproduce the published protected header from the published unprotected header.
    auto unprotected = hex(kUnprotectedHeader);
    const std::size_t pn_offset = unprotected.size() - 4;
    unprotected[0] = static_cast<std::uint8_t>(unprotected[0] ^ (mask[0] & 0x0fu));
    for (std::size_t i = 0; i < 4; ++i) {
        unprotected[pn_offset + i] =
            static_cast<std::uint8_t>(unprotected[pn_offset + i] ^ mask[1 + i]);
    }
    ZC_CHECK_EQ(to_hex(unprotected), std::string(kProtectedHeader));
}

void check_encrypt_matches_rfc() {
    using namespace zctest::rfc9001;
    const auto keys = zc::quic_initial_keys(0x00000001u, hex(kDcid));
    ZC_REQUIRE(keys.has_value());

    // Rebuild the 1162-byte unprotected payload: the published CRYPTO frame followed by
    // PADDING frames up to the length RFC 9001 A.2 states.
    std::vector<std::uint8_t> payload = hex(kCryptoFrame);
    ZC_REQUIRE(payload.size() == 245);
    payload.resize(1162, 0x00);

    const auto aad = hex(kUnprotectedHeader);
    const std::uint64_t packet_number = 2;  // RFC 9001 A.2

    std::array<std::uint8_t, 12> nonce = keys->iv;
    for (std::size_t i = 0; i < 8; ++i) {
        nonce[11 - i] = static_cast<std::uint8_t>(nonce[11 - i] ^
                                                static_cast<std::uint8_t>((packet_number >> (8u * i)) & 0xffu));
    }

    std::vector<std::uint8_t> ciphertext(payload.size());
    std::array<std::uint8_t, 16> tag{};
    zc::crypto::aes128_gcm_encrypt(keys->key, nonce, aad, payload, ciphertext,
                                   std::span<std::uint8_t>(tag));

    // Compare against the published protected packet: skip the 18-byte header and the
    // 4-byte (protected) packet number, then compare all 1162 published ciphertext bytes.
    const auto published = hex(kProtectedPacket);
    constexpr std::size_t kHeaderLen = 18;
    constexpr std::size_t kPacketNumberLen = 4;
    ZC_REQUIRE(published.size() > kHeaderLen + kPacketNumberLen);
    const std::span<const std::uint8_t> published_ciphertext(
        published.data() + kHeaderLen + kPacketNumberLen,
        published.size() - kHeaderLen - kPacketNumberLen);

    ZC_CHECK_EQ(published_ciphertext.size(), ciphertext.size());
    std::size_t first_diff = ciphertext.size();
    for (std::size_t i = 0; i < std::min(ciphertext.size(), published_ciphertext.size()); ++i) {
        if (ciphertext[i] != published_ciphertext[i]) {
            first_diff = i;
            break;
        }
    }
    if (first_diff != ciphertext.size()) {
        std::printf("       first difference at byte %zu: mine=%02x rfc=%02x\n", first_diff,
                    ciphertext[first_diff], published_ciphertext[first_diff]);
        std::printf("       mine: %s\n", to_hex(std::span<const std::uint8_t>(ciphertext).first(32)).c_str());
        std::printf("       rfc : %s\n", to_hex(published_ciphertext.first(32)).c_str());
    }
    ZC_CHECK_MSG(first_diff == ciphertext.size(),
                 "re-encryption must reproduce the RFC ciphertext byte for byte");
}

void check_decrypt_rfc() {
    using namespace zctest::rfc9001;
    // The published excerpt omits the 16-byte AEAD tag, so reconstruct it by
    // re-encrypting the published plaintext; everything before it is the RFC's bytes.
    const auto keys = zc::quic_initial_keys(0x00000001u, hex(kDcid));
    ZC_REQUIRE(keys.has_value());
    std::vector<std::uint8_t> payload = hex(kCryptoFrame);
    payload.resize(1162, 0x00);
    const auto aad = hex(kUnprotectedHeader);
    std::array<std::uint8_t, 12> nonce = keys->iv;
    nonce[11] = static_cast<std::uint8_t>(nonce[11] ^ 0x02);
    std::vector<std::uint8_t> ct(payload.size());
    std::array<std::uint8_t, 16> tag{};
    zc::crypto::aes128_gcm_encrypt(keys->key, nonce, aad, payload, ct,
                                   std::span<std::uint8_t>(tag));

    std::vector<std::uint8_t> packet = hex(kProtectedPacket);
    packet.insert(packet.end(), tag.begin(), tag.end());
    ZC_CHECK_EQ(packet.size(), 1200u);

    const zc::QuicPacket q = zc::parse_quic(packet);
    ZC_REQUIRE(q.valid);
    ZC_CHECK(q.long_header && q.fixed_bit);
    ZC_CHECK(q.version_known);
    ZC_CHECK(q.type == zc::QuicPacketType::initial);
    ZC_CHECK_EQ(q.version, 0x00000001u);
    ZC_CHECK_EQ(q.dcid_length, 8u);
    ZC_CHECK_EQ(q.scid_length, 0u);
    ZC_CHECK_EQ(q.token_length, 0u);
    ZC_CHECK_EQ(q.length, 1182u);
    ZC_CHECK_EQ(q.packet_number_offset, 18u);
    ZC_CHECK_EQ(q.packet_end, packet.size());

    std::vector<std::uint8_t> frames;
    std::uint64_t pn = 0;
    ZC_REQUIRE(zc::decrypt_quic_initial(packet, q, 0, frames, pn));
    ZC_CHECK_EQ(pn, 2u);
    ZC_CHECK_EQ(frames.size(), 1162u);
    ZC_CHECK_MSG(to_hex(frames) == to_hex(payload),
                 "decrypted payload must equal the RFC plaintext");

    // CRYPTO frame -> ClientHello -> SNI.
    zc::CryptoStream stream;
    stream.adopt_connection(q.version,
                            std::span<const std::uint8_t>(packet).subspan(q.dcid_offset,
                                                                         q.dcid_length));
    ZC_CHECK(stream.add_frames(frames));
    std::string sni;
    ZC_CHECK(stream.client_hello_sni(sni));
    ZC_CHECK_EQ(sni, std::string("example.com"));
    ZC_CHECK(stream.complete());

    // Single-bit tampering anywhere in the protected region must fail authentication.
    for (std::size_t offset : {std::size_t{0}, std::size_t{17}, std::size_t{22},
                               packet.size() / 2, packet.size() - 1}) {
        auto bad = packet;
        bad[offset] = static_cast<std::uint8_t>(bad[offset] ^ 0x01u);
        std::vector<std::uint8_t> junk;
        std::uint64_t ignored = 0;
        ZC_CHECK_MSG(!zc::decrypt_quic_initial(bad, zc::parse_quic(bad), 0, junk, ignored),
                     "tampered byte at " + std::to_string(offset));
    }

    // Deriving keys from a different DCID must fail.
    auto wrong_dcid = q;
    wrong_dcid.dcid_offset = q.dcid_offset + 1;
    std::vector<std::uint8_t> junk;
    std::uint64_t ignored = 0;
    ZC_CHECK(!zc::decrypt_quic_initial(packet, wrong_dcid, 0, junk, ignored));
}

void check_header_parsing_robustness() {
    const auto packet = hex(zctest::rfc9001::kProtectedPacket);

    // A zero fixed bit is forbidden by RFC 8999 and must be rejected outright.
    std::array<std::uint8_t, 64> no_fixed{};
    no_fixed[0] = 0x80;
    no_fixed[4] = 0x01;
    ZC_CHECK(!zc::parse_quic(no_fixed).valid);

    // Short header (1-RTT) is recognised but is never an Initial.
    const std::array<std::uint8_t, 32> short_header{};
    const zc::QuicPacket sh = zc::parse_quic(short_header);
    ZC_CHECK(sh.valid && !sh.long_header && sh.type == zc::QuicPacketType::one_rtt);

    // Truncation at any point must never yield a valid Initial.
    for (std::size_t cut : {std::size_t{0}, std::size_t{1}, std::size_t{5}, std::size_t{7},
                            std::size_t{15}, std::size_t{17}, std::size_t{18},
                            std::size_t{19}, std::size_t{20}, std::size_t{100},
                            packet.size() - 1}) {
        ZC_CHECK_MSG(!zc::parse_quic(std::span<const std::uint8_t>(packet).first(cut)).valid,
                     "truncated to " + std::to_string(cut));
    }

    // An unknown version must be refused instead of guessing the type mapping.
    auto unknown = packet;
    unknown[1] = 0x11; unknown[2] = 0x22; unknown[3] = 0x33; unknown[4] = 0x44;
    ZC_CHECK(!zc::parse_quic(unknown).valid);

    // The Initial packet type encoding is version specific: for v1 the type bits 0b00
    // mean Initial, for v2 the same bits mean 0-RTT. A parser that ignores this will
    // happily try to decrypt something it should not.
    ZC_REQUIRE(packet.size() <= 1200);
    std::vector<std::uint8_t> full = packet;
    full.resize(1200, 0x00);
    auto v2 = full;
    v2[1] = 0x6b; v2[2] = 0x33; v2[3] = 0x43; v2[4] = 0xcf;  // 0x6b3343cf
    v2[0] = 0xc0;  // type bits 0b00
    ZC_CHECK(zc::parse_quic(v2).valid);
    ZC_CHECK(zc::parse_quic(v2).version_known);
    ZC_CHECK(zc::parse_quic(v2).type == zc::QuicPacketType::zero_rtt);
    v2[0] = 0xd0;  // type bits 0b01 -> Initial for v2
    ZC_CHECK(zc::parse_quic(v2).valid);
    ZC_CHECK(zc::parse_quic(v2).type == zc::QuicPacketType::initial);
    ZC_CHECK(zc::parse_quic(full).type == zc::QuicPacketType::initial);  // v1

    // Connection IDs longer than 20 bytes must be refused.
    auto long_cid = packet;
    long_cid[5] = 21;
    ZC_CHECK(!zc::parse_quic(long_cid).valid);

    // A Length field that overruns the datagram must be refused.
    auto lying_length = packet;
    lying_length[16] = 0x7f;
    lying_length[17] = 0xff;
    ZC_CHECK(!zc::parse_quic(lying_length).valid);
    // ...and accepted once the buffer really is that long.
    std::vector<std::uint8_t> big = lying_length;
    big.resize(1200 + 0x3fff, 0x00);
    ZC_CHECK(zc::parse_quic(big).valid);

    // A zero Length field is invalid.
    auto zero_length = packet;
    zero_length[16] = 0x40;
    zero_length[17] = 0x00;
    ZC_CHECK(!zc::parse_quic(zero_length).valid);

    // Random UDP noise must essentially never be classified as an Initial.
    std::uint32_t rng = 0x12345678u;
    int false_positives = 0;
    for (int i = 0; i < 4096; ++i) {
        std::vector<std::uint8_t> noise(64 + (i % 64));
        for (std::uint8_t& b : noise) {
            rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
            b = static_cast<std::uint8_t>(rng & 0xffu);
        }
        const zc::QuicPacket n = zc::parse_quic(noise);
        if (n.valid && n.type == zc::QuicPacketType::initial) ++false_positives;
    }
    ZC_CHECK_MSG(false_positives == 0,
                 "random UDP produced " + std::to_string(false_positives) +
                     " Initial candidates (must be 0)");
}

void append_varint(std::vector<std::uint8_t>& out, std::uint64_t v) {
    if (v <= 63) {
        out.push_back(static_cast<std::uint8_t>(v));
    } else if (v <= 16383) {
        out.push_back(static_cast<std::uint8_t>(0x40u | ((v >> 8) & 0x3fu)));
        out.push_back(static_cast<std::uint8_t>(v & 0xffu));
    } else {
        out.push_back(static_cast<std::uint8_t>(0x80u | ((v >> 24) & 0x3fu)));
        out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xffu));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xffu));
        out.push_back(static_cast<std::uint8_t>(v & 0xffu));
    }
}

std::vector<std::uint8_t> crypto_frame(std::uint64_t offset,
                                       std::span<const std::uint8_t> data) {
    std::vector<std::uint8_t> f;
    append_varint(f, 0x06);
    append_varint(f, offset);
    append_varint(f, data.size());
    f.insert(f.end(), data.begin(), data.end());
    return f;
}

void check_crypto_stream_reassembly() {
    // kCryptoFrame is a whole CRYPTO frame; the reassembly tests need just its payload.
    const auto frame_bytes = hex(zctest::rfc9001::kCryptoFrame);
    ZC_REQUIRE(frame_bytes.size() == 245);
    const std::vector<std::uint8_t> content(frame_bytes.begin() + 4, frame_bytes.end());
    std::string sni;

    // A ClientHello that is not fully present must never produce an SNI. This is the
    // property the engine relies on to avoid acting on half-parsed input.
    for (std::size_t cut = 4; cut < content.size(); cut += 7) {
        zc::CryptoStream partial;
        partial.add_frames(crypto_frame(0, std::span<const std::uint8_t>(content).first(cut)));
        ZC_CHECK_MSG(!partial.client_hello_sni(sni),
                     "truncated CRYPTO payload of " + std::to_string(cut) +
                         " bytes must not yield an SNI");
    }

    // The complete payload yields the SNI.
    {
        zc::CryptoStream whole;
        whole.add_frames(crypto_frame(0, content));
        ZC_CHECK(whole.client_hello_sni(sni));
        ZC_CHECK_EQ(sni, std::string("example.com"));
        ZC_CHECK(whole.complete());
    }

    // Out-of-order CRYPTO offsets must reassemble correctly: the tail arrives first.
    const std::size_t half = content.size() / 2;
    zc::CryptoStream split;
    split.add_frames(crypto_frame(half, std::span<const std::uint8_t>(content).subspan(half)));
    ZC_CHECK(!split.client_hello_sni(sni));
    split.add_frames(crypto_frame(0, std::span<const std::uint8_t>(content).first(half)));
    ZC_CHECK(split.client_hello_sni(sni));
    ZC_CHECK_EQ(sni, std::string("example.com"));

    // Duplicate CRYPTO data must be idempotent, not corrupt the stream.
    zc::CryptoStream dup;
    const auto frame = crypto_frame(0, content);
    dup.add_frames(frame);
    dup.add_frames(frame);
    dup.add_frames(frame);
    ZC_CHECK(dup.client_hello_sni(sni));
    ZC_CHECK_EQ(sni, std::string("example.com"));

    // PADDING frames in front of the CRYPTO frame must be skipped, not mis-parsed.
    {
        std::vector<std::uint8_t> stream_bytes = {0x00, 0x00, 0x00, 0x01};  // PADDING, PING
        stream_bytes.insert(stream_bytes.end(), frame.begin(), frame.end());
        zc::CryptoStream padded;
        padded.add_frames(stream_bytes);
        ZC_CHECK(padded.client_hello_sni(sni));
        ZC_CHECK_EQ(sni, std::string("example.com"));
    }

    // An ACK frame ahead of the CRYPTO frame must be walked over correctly.
    {
        std::vector<std::uint8_t> ack = {0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};  // ACK, 1 range
        ack.insert(ack.end(), frame.begin(), frame.end());
        zc::CryptoStream acked;
        acked.add_frames(ack);
        ZC_CHECK(acked.client_hello_sni(sni));
        ZC_CHECK_EQ(sni, std::string("example.com"));
    }

    // Malformed and hostile frame streams must be ignored, never crash or spin.
    zc::CryptoStream hostile;
    for (std::size_t n = 1; n <= 48; ++n) {
        std::vector<std::uint8_t> garbage(n, 0xff);
        hostile.add_frames(garbage);
        (void)hostile.client_hello_sni(sni);
    }
    // CRYPTO frame whose declared length runs past the buffer.
    zc::CryptoStream lying;
    lying.add_frames(std::span<const std::uint8_t>(std::array<std::uint8_t,5>{0x06,0x00,0x40,0x00,0x00}));
    ZC_CHECK(!lying.client_hello_sni(sni));
    // ACK frame claiming a huge number of ranges.
    zc::CryptoStream huge_ack;
    huge_ack.add_frames(std::span<const std::uint8_t>(std::array<std::uint8_t,7>{0x02,0x00,0x00,0x7f,0xff,0xff,0x00}));
    ZC_CHECK(!huge_ack.client_hello_sni(sni));
    // A CRYPTO frame at an absurd offset must be dropped, not allocated.
    zc::CryptoStream far_offset;
    far_offset.add_frames(crypto_frame(1u << 20, content));
    ZC_CHECK(!far_offset.client_hello_sni(sni));
    ZC_CHECK(far_offset.stored_bytes() == 0);
    // Empty input.
    zc::CryptoStream empty;
    empty.add_frames(std::span<const std::uint8_t>());
    ZC_CHECK(!empty.client_hello_sni(sni));
    // Bytes that are not a ClientHello at all.
    zc::CryptoStream not_hello;
    not_hello.add_frames(crypto_frame(0, hex("02 00 00 05 aabbccddee")));
    ZC_CHECK(!not_hello.client_hello_sni(sni));

    // A Retry invalidates the connection: previously collected bytes must be dropped.
    zc::CryptoStream retried;
    retried.adopt_connection(0x00000001u, hex(zctest::rfc9001::kDcid));
    retried.add_frames(frame);
    ZC_CHECK(retried.client_hello_sni(sni));
    retried.adopt_connection(0x00000001u, hex("0011223344556677"));
    ZC_CHECK(retried.connection_changed());
    ZC_CHECK(!retried.client_hello_sni(sni));
    ZC_CHECK(retried.stored_bytes() == 0);

    // The memory budget must be enforced even for a stream full of garbage.
    zc::CryptoStream flood;
    for (int i = 0; i < 64; ++i) {
        std::vector<std::uint8_t> chunk(512, static_cast<std::uint8_t>(i));
        flood.add_frames(crypto_frame(0, chunk));
    }
    ZC_CHECK_MSG(flood.stored_bytes() <= 8192,
                 "CRYPTO buffer must stay bounded, got " + std::to_string(flood.stored_bytes()));
}

void check_decoy_roundtrip() {
    // A generated decoy must be indistinguishable from a real client Initial to any
    // RFC 9001 implementation.
    const auto decoy = zc::build_quic_client_initial("www.microsoft.com", 1200, 0x1234abcd);
    ZC_REQUIRE(decoy.size() == 1200);
    const zc::QuicPacket q = zc::parse_quic(decoy);
    ZC_REQUIRE(q.valid && q.type == zc::QuicPacketType::initial);
    ZC_CHECK_EQ(q.packet_end, decoy.size());
    ZC_CHECK(q.packet_end - q.packet_number_offset >= 1 + 16);

    std::vector<std::uint8_t> frames;
    std::uint64_t pn = 0;
    ZC_REQUIRE(zc::decrypt_quic_initial(decoy, q, 0, frames, pn));
    ZC_CHECK_EQ(pn, 0u);

    zc::CryptoStream stream;
    stream.adopt_connection(q.version, std::span<const std::uint8_t>(decoy).subspan(
                                            q.dcid_offset, q.dcid_length));
    ZC_CHECK(stream.add_frames(frames));
    std::string sni;
    ZC_CHECK(stream.client_hello_sni(sni));
    ZC_CHECK_EQ(sni, std::string("www.microsoft.com"));

    // A single flipped ciphertext bit must break the decoy: it is really authenticated.
    auto broken = decoy;
    broken[broken.size() - 20] = static_cast<std::uint8_t>(broken[broken.size() - 20] ^ 0x08u);
    std::vector<std::uint8_t> junk;
    std::uint64_t ignored = 0;
    ZC_CHECK(!zc::decrypt_quic_initial(broken, zc::parse_quic(broken), 0, junk, ignored));

    // Minimum-size and maximum-size decoys.
    for (std::size_t size : {std::size_t{1200}, std::size_t{1400}, std::size_t{4096}}) {
        const auto d = zc::build_quic_client_initial("decoy.example", size, 7);
        ZC_REQUIRE(d.size() == size);
        std::vector<std::uint8_t> f2;
        std::uint64_t p2 = 0;
        const zc::QuicPacket q2 = zc::parse_quic(d);
        ZC_CHECK(q2.valid);
        ZC_CHECK(zc::decrypt_quic_initial(d, q2, 0, f2, p2));
        zc::CryptoStream cs;
        cs.adopt_connection(q2.version, std::span<const std::uint8_t>(d).subspan(
                                              q2.dcid_offset, q2.dcid_length));
        cs.add_frames(f2);
        ZC_CHECK(cs.client_hello_sni(sni));
        ZC_CHECK_EQ(sni, std::string("decoy.example"));
    }

    // Refuses invalid input rather than emitting nonsense.
    ZC_CHECK(zc::build_quic_client_initial("", 1200, 1).empty());
    ZC_CHECK(zc::build_quic_client_initial("bad host", 1200, 1).empty());
    ZC_CHECK(zc::build_quic_client_initial("a..b", 1200, 1).empty());
}

void check_client_hello_builder() {
    std::array<std::uint8_t, 512> buf{};
    const std::size_t n = zc::build_client_hello(buf, "example.org", 0xdeadbeef);
    ZC_REQUIRE(n > 0);
    const zc::TlsClientHello hello = zc::parse_tls(std::span<const std::uint8_t>(buf).first(n));
    ZC_CHECK(hello.is_tls && hello.is_client_hello && hello.hello_complete);
    ZC_CHECK(hello.has_sni);
    ZC_CHECK_EQ(hello.sni, std::string("example.org"));
    ZC_CHECK(!hello.encrypted_client_hello);

    // Too small an output buffer must be refused, never overflowed.
    std::array<std::uint8_t, 8> tiny{};
    ZC_CHECK_EQ(zc::build_client_hello(tiny, "example.org", 1), 0u);
    std::array<std::uint8_t, 128> small{};
    ZC_CHECK_EQ(zc::build_client_hello(small, std::string(100, 'a'), 1), 0u);
    // A 253-byte hostname must fit.
    std::array<std::uint8_t, 512> big{};
    ZC_CHECK(zc::build_client_hello(big, std::string(63, 'a') + "." +
                                                std::string(63, 'b') + "." +
                                                std::string(63, 'c') + "." +
                                                std::string(61, 'd'),
                                    5) != 0);
}

void run() {
    check_key_derivation();
    check_header_protection();
    check_encrypt_matches_rfc();
    check_decrypt_rfc();
    check_header_parsing_robustness();
    check_crypto_stream_reassembly();
    check_decoy_roundtrip();
    check_client_hello_builder();
}

}  // namespace

ZC_TEST_MAIN("quic", run)
