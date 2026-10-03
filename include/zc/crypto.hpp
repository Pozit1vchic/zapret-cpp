// Minimal, self-contained crypto primitives needed to *read* QUIC Initial packets.
//
// Why this exists: QUIC v1/v2 Initial packets are protected with keys derived only
// from the client's Destination Connection ID (RFC 9001 section 5.2), so any observer
// can remove Initial protection and recover the TLS ClientHello carried in CRYPTO
// frames. That turns "QUIC is opaque, we cannot match hostnames" into "QUIC is
// hostname-visible", which is what makes host rules work for HTTP/3.
//
// Implemented here instead of pulling in a crypto dependency:
//   * SHA-256 / HMAC-SHA-256  (FIPS 180-4, RFC 2104)
//   * HKDF-Extract / HKDF-Expand / HKDF-Expand-Label  (RFC 5869, RFC 8446 7.1)
//   * AES-128 block encryption (FIPS 197)
//   * AES-128-GCM with a 12-byte nonce and 16-byte tag (NIST SP 800-38D)
//
// All functions are constant-shape and allocation free. They are verified against the
// published test vectors in tests/test_crypto.cpp and against the RFC 9001 Appendix A
// client Initial packet in tests/test_quic.cpp.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace zc::crypto {

using Bytes16 = std::array<std::uint8_t, 16>;
using Bytes32 = std::array<std::uint8_t, 32>;

class Sha256 {
public:
    Sha256() noexcept { reset(); }
    void reset() noexcept;
    void update(std::span<const std::uint8_t> data) noexcept;
    void finish(Bytes32& out) noexcept;  // non-destructive enough for one-shot use

private:
    void compress(const std::uint8_t block[64]) noexcept;

    std::uint32_t h_[8]{};
    std::uint8_t buffer_[64]{};
    std::size_t buffered_ = 0;
    std::uint64_t total_bits_ = 0;
};

[[nodiscard]] Bytes32 sha256(std::span<const std::uint8_t> data) noexcept;

[[nodiscard]] Bytes32 hmac_sha256(std::span<const std::uint8_t> key,
                                   std::span<const std::uint8_t> data) noexcept;

// RFC 5869
[[nodiscard]] Bytes32 hkdf_extract(std::span<const std::uint8_t> salt,
                                   std::span<const std::uint8_t> ikm) noexcept;
void hkdf_expand(std::span<const std::uint8_t> prk, std::span<const std::uint8_t> info,
                 std::span<std::uint8_t> out) noexcept;

// RFC 8446 section 7.1 HKDF-Expand-Label, always with an ASCII label prefix "tls13 ".
void hkdf_expand_label(std::span<const std::uint8_t> secret, std::string_view label,
                       std::span<const std::uint8_t> context, std::span<std::uint8_t> out);

// Convenience wrapper for the common "derive a 32-byte secret" case (QUIC initial
// secrets, TLS traffic secrets).
[[nodiscard]] Bytes32 hkdf_expand_label_value(std::span<const std::uint8_t> secret,
                                               std::string_view label) noexcept;

// --- AES-128 ------------------------------------------------------------------

class Aes128 {
public:
    explicit Aes128(std::span<const std::uint8_t> key) noexcept;

    void encrypt_block(std::span<const std::uint8_t> in,
                       std::span<std::uint8_t> out) const noexcept;
    void decrypt_block(std::span<const std::uint8_t> in,
                       std::span<std::uint8_t> out) const noexcept;

private:
    std::uint32_t round_keys_[44]{};
};

// AES-128-GCM. `nonce` must be 12 bytes, `tag` is 16 bytes.
void aes128_gcm_encrypt(std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
                        std::span<const std::uint8_t> aad,
                        std::span<const std::uint8_t> plaintext,
                        std::span<std::uint8_t> ciphertext, std::span<std::uint8_t> tag) noexcept;

[[nodiscard]] bool aes128_gcm_decrypt(std::span<const std::uint8_t> key,
                                     std::span<const std::uint8_t> nonce,
                                     std::span<const std::uint8_t> aad,
                                     std::span<const std::uint8_t> ciphertext,
                                     std::span<const std::uint8_t> tag,
                                     std::span<std::uint8_t> plaintext) noexcept;

// Multiply y (in/out) by H in GF(2^128). `x` is modified in place.
void ghash_mul(std::span<std::uint8_t> x, std::span<const std::uint8_t> h) noexcept;

}  // namespace zc::crypto
