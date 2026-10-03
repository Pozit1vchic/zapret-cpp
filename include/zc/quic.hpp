// QUIC packet header parsing plus *real* Initial packet protection removal.
//
// Why this is not "a parser that looks at a few bytes":
//   * QUIC v1 (0x00000001) and v2 (0x6b3343cf) use different initial salts, different
//     HKDF labels and different long-header packet-type encodings. Unknown versions are
//     rejected rather than guessed.
//   * For an Initial packet the keys are derived purely from the client's Destination
//     Connection ID (RFC 9001 section 5.2), so header protection can be removed and the
//     payload decrypted by any observer. Only then is the TLS ClientHello reachable.
//   * The ClientHello is carried in CRYPTO frames; the ClientHello can span several
//     Initial packets, so `CryptoStream` performs offset-based reassembly.
//
// Anything that fails validation (bad fixed bit, absurd length, truncated datagram,
// unknown version, authentication failure) returns "not an Initial" so the caller
// falls back to passing the packet through untouched.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace zc {

inline constexpr std::size_t kQuicMaxConnectionId = 20;
inline constexpr std::size_t kQuicMinimumInitialSize = 1200;

enum class QuicPacketType : std::uint8_t {
    unknown = 0,
    initial,
    zero_rtt,
    handshake,
    retry,
    version_negotiation,
    one_rtt,
};

struct QuicPacket {
    bool valid = false;
    bool long_header = false;
    bool fixed_bit = false;
    QuicPacketType type = QuicPacketType::unknown;
    std::uint32_t version = 0;
    std::uint8_t first_byte = 0;  // as received (header-protected)
    std::size_t dcid_offset = 0, dcid_length = 0;
    std::size_t scid_offset = 0, scid_length = 0;
    std::size_t token_offset = 0, token_length = 0;
    std::size_t length_offset = 0, length_field_size = 0;
    std::uint64_t length = 0;              // packet number + payload + tag
    std::size_t packet_number_offset = 0;  // start of the (protected) PN field
    std::size_t packet_end = 0;            // one past the end of this packet
    bool version_known = false;            // v1 or v2: type mapping and keys are defined
};

[[nodiscard]] QuicPacket parse_quic(std::span<const std::uint8_t> datagram) noexcept;

[[nodiscard]] bool quic_version_known(std::uint32_t version) noexcept;

// RFC 9001 5.2 / RFC 9369 3.3.
struct QuicInitialKeys {
    std::array<std::uint8_t, 16> key{};
    std::array<std::uint8_t, 12> iv{};
    std::array<std::uint8_t, 16> hp{};
};

[[nodiscard]] std::optional<QuicInitialKeys> quic_initial_keys(
    std::uint32_t version, std::span<const std::uint8_t> dcid) noexcept;

// Remove header protection in place on a copy of `datagram` and decrypt the payload.
// `largest_packet_number` feeds RFC 9000 Appendix A.3 truncation recovery.
// Returns the decrypted frames on success.
[[nodiscard]] bool decrypt_quic_initial(std::span<const std::uint8_t> datagram,
                                        const QuicPacket& packet,
                                        std::uint64_t largest_packet_number,
                                        std::vector<std::uint8_t>& frames,
                                        std::uint64_t& packet_number) noexcept;

// Offset-indexed reassembly buffer for one encryption level's CRYPTO stream.
class CryptoStream {
public:
    // A Retry forces the client to derive new Initial keys from a new DCID, at which
    // point previously collected CRYPTO data belongs to a different secret stream.
    void reset() noexcept;
    void adopt_connection(std::uint32_t version, std::span<const std::uint8_t> dcid) noexcept;

    // Parse decrypted frames and insert any CRYPTO frame payloads. Returns true when
    // the stream changed.
    bool add_frames(std::span<const std::uint8_t> frames) noexcept;

    // Extract the SNI once the ClientHello is fully reassembled.
    [[nodiscard]] bool client_hello_sni(std::string& sni) const noexcept;
    [[nodiscard]] std::size_t contiguous_bytes() const noexcept { return end_offset_; }
    [[nodiscard]] std::size_t stored_bytes() const noexcept { return stored_; }
    [[nodiscard]] bool complete() const noexcept { return complete_; }
    [[nodiscard]] bool connection_changed() const noexcept { return connection_changed_; }

private:
    static constexpr std::size_t kMaxCryptoBytes = 8192;

    std::vector<std::uint8_t> data_;
    std::vector<bool> present_;
    std::size_t end_offset_ = 0;
    std::size_t stored_ = 0;
    bool complete_ = false;
    bool connection_changed_ = false;
    std::uint32_t version_ = 0;
    std::vector<std::uint8_t> dcid_;
};

// Build a fully protected client Initial packet carrying `sni`, ready to be wrapped in
// UDP/IP. The result is decodable by any RFC 9001 implementation, which is the point:
// a decoy that only looks like QUIC on the surface teaches a DPI nothing.
[[nodiscard]] std::vector<std::uint8_t> build_quic_client_initial(
    std::string_view sni, std::size_t target_size, std::uint32_t random_seed) noexcept;

}  // namespace zc
