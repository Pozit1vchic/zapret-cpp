// TLS record layer + ClientHello/SNI parsing.
//
// Safety contract: every read is bounds-checked against the supplied span. The
// parser never dereferences out of range and never allocates unbounded memory.
// A ClientHello that is not fully present is reported as `record_complete == false`
// with `has_sni == false`; callers must treat that as "hostname unknown" and, in the
// default fail-open mode, must pass the packet through untouched.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace zc {

inline constexpr std::size_t kMaxTlsRecordBody = 16640;  // 2^14 + slack for protected records
inline constexpr std::size_t kMaxTlsPrefixRecords = 8;    // CCS + handshake records we will skip

enum class TlsContentType : std::uint8_t {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
};

struct TlsClientHello {
    // Classification
    bool is_tls = false;           // a plausible TLS handshake record
    bool is_client_hello = false;  // handshake type 1
    bool record_complete = false;  // the whole TLS record is inside the span
    bool hello_complete = false;   // the whole ClientHello body is inside the span

    // Identity
    bool sni_present = false;      // an SNI extension with a non-empty host_name entry
    bool has_sni = false;          // ... and the name passed hostname validation
    std::string sni;               // lower-cased, no trailing dot
    bool sni_is_ip_literal = false;
    bool encrypted_client_hello = false;  // extension 0xfe0d present

    // Geometry (offsets are relative to the span handed to parse_tls)
    std::size_t tls_offset = 0;           // first byte of the handshake record header
    std::size_t record_length = 0;        // 5 + TLSPlaintext.length
    std::size_t hello_body_offset = 0;    // first byte of the ClientHello body
    std::size_t hello_body_length = 0;    // declared handshake body length
    std::size_t sni_offset = 0;           // first byte of the SNI bytes
    std::size_t sni_length = 0;
    std::size_t extensions_offset = 0;    // first byte of the extensions block
    std::size_t extensions_length = 0;
    std::size_t cipher_suites_offset = 0;
    std::size_t cipher_suites_length = 0;
    std::uint8_t session_id_length = 0;

    std::uint16_t record_version = 0;     // TLSPlaintext.legacy_record_version
    std::uint16_t legacy_version = 0;     // ClientHello.legacy_version

    // How many additional bytes of the same stream would complete the ClientHello.
    // 0 when the ClientHello is already complete.
    std::size_t missing_bytes = 0;

    [[nodiscard]] bool usable() const noexcept { return is_tls && is_client_hello; }
};

[[nodiscard]] TlsClientHello parse_tls(std::span<const std::uint8_t> data) noexcept;

// Parse a bare ClientHello *handshake body* (starting at legacy_version), i.e. what a
// QUIC CRYPTO frame carries. Offsets in the result are relative to `body`. QUIC does
// not use TLS records, so parse_tls() cannot be used for it; this entry point is the
// shared core both paths use.
[[nodiscard]] TlsClientHello parse_client_hello_body(std::span<const std::uint8_t> body) noexcept;

// Build a syntactically valid TLS ClientHello record carrying `sni`.
// Used for QUIC Initial decoys and for TCP decoys when the real ClientHello has no
// usable SNI. Returns the number of bytes written, or 0 if `out` is too small.
[[nodiscard]] std::size_t build_client_hello(std::span<std::uint8_t> out, std::string_view sni,
                                             std::uint32_t random_seed) noexcept;

// Hostname syntax validation shared by TLS SNI, HTTP Host and rule files.
// Accepts DNS names only: LDH labels, no trailing dot, <= 253 bytes.
[[nodiscard]] bool is_valid_hostname(std::string_view host) noexcept;

// Lower-case, strip a single trailing dot. Rejects invalid names via nullopt.
[[nodiscard]] std::optional<std::string> normalize_hostname(std::string_view host) noexcept;

// Build a syntactically valid hostname of exactly `target_len` bytes that ends with
// `suffix` when possible. Used to construct same-length TLS/HTTP decoys without
// changing record framing. Returns nullopt when no valid name of that length exists.
[[nodiscard]] std::optional<std::string> fit_hostname(std::string_view suffix,
                                                      std::size_t target_len) noexcept;

}  // namespace zc
