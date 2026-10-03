#include "zc/quic.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "zc/crypto.hpp"
#include "zc/packet.hpp"
#include "zc/tls.hpp"

namespace zc {
namespace {

constexpr std::uint32_t kQuicV1 = 0x00000001u;
constexpr std::uint32_t kQuicV2 = 0x6b3343cfu;

// RFC 9001 5.2 (v1) and RFC 9369 3.3.1 (v2).
constexpr std::uint8_t kInitialSaltV1[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                             0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
                                             0xad, 0xcc, 0xbb, 0x7f, 0x0a};
constexpr std::uint8_t kInitialSaltV2[20] = {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6,
                                             0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
                                             0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9};

// The long-header packet type encoding is version specific.
//
// RFC 9000 section 17.2 (v1):   Initial 0b00, 0-RTT 0b01, Handshake 0b10, Retry 0b11
// RFC 9369 section 3.2   (v2):   0-RTT   0b00, Initial  0b01, Retry   0b10, Handshake 0b11
//
// The table is therefore indexed by the raw 2-bit field value rather than by "which
// version is this the Nth packet type of", because the v2 permutation is exactly the
// kind of detail a parser must get right.
struct TypeMapping {
    QuicPacketType by_bits[4];
    const char* key_label;
    const char* iv_label;
    const char* hp_label;
    const std::uint8_t* salt;
};

bool type_mapping_for(std::uint32_t version, TypeMapping& out) noexcept {
    if (version == kQuicV1) {
        out = {{QuicPacketType::initial, QuicPacketType::zero_rtt, QuicPacketType::handshake,
                QuicPacketType::retry},
               "quic key", "quic iv", "quic hp", kInitialSaltV1};
        return true;
    }
    if (version == kQuicV2) {
        out = {{QuicPacketType::zero_rtt, QuicPacketType::initial, QuicPacketType::retry,
                QuicPacketType::handshake},
               "quicv2 key", "quicv2 iv", "quicv2 hp", kInitialSaltV2};
        return true;
    }
    return false;
}

QuicPacketType type_from_bits(std::uint32_t version, std::uint8_t bits) noexcept {
    TypeMapping m{};
    if (!type_mapping_for(version, m)) return QuicPacketType::unknown;
    return m.by_bits[bits & 0x03u];
}

std::uint32_t xorshift32(std::uint32_t& state) noexcept {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

bool read_varint(std::span<const std::uint8_t> d, std::size_t& off, std::uint64_t& value,
                 std::size_t& encoded) noexcept {
    if (off >= d.size()) return false;
    encoded = static_cast<std::size_t>(1u << (d[off] >> 6));
    if (encoded > 8 || encoded > d.size() - off) return false;
    value = static_cast<std::uint64_t>(d[off] & 0x3fu);
    for (std::size_t i = 1; i < encoded; ++i) {
        value = (value << 8) | d[off + i];
    }
    off += encoded;
    return true;
}

std::size_t varint_size_for(std::uint64_t value) noexcept {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823ull) return 4;
    if (value <= 4611686018427387903ull) return 8;
    return 0;
}

void append_varint(std::vector<std::uint8_t>& out, std::uint64_t value) {
    const std::size_t n = varint_size_for(value);
    if (n == 0) return;
    std::uint8_t buf[8] = {};
    std::uint64_t v = value;
    for (std::size_t i = 0; i < n; ++i) {
        buf[n - 1 - i] = static_cast<std::uint8_t>(v & 0xffu);
        v >>= 8;
    }
    const std::uint8_t prefix = n == 1 ? 0x00 : n == 2 ? 0x40 : n == 4 ? 0x80 : 0xc0;
    buf[0] = static_cast<std::uint8_t>((buf[0] & 0x3fu) | prefix);
    out.insert(out.end(), buf, buf + n);
}

// RFC 9000 Appendix A.3: recover a truncated packet number.
std::uint64_t reconstruct_packet_number(std::uint64_t truncated, std::size_t pn_len,
                                        std::uint64_t largest) noexcept {
    if (pn_len == 0 || pn_len >= 8) return truncated;
    const std::uint64_t window = 1ull << (pn_len * 8);
    const std::uint64_t half = window / 2;
    const std::uint64_t candidate = (largest & ~(window - 1)) | truncated;
    if (candidate + half <= largest && candidate + window < (1ull << 62)) return candidate + window;
    if (candidate > largest + half && candidate >= window) return candidate - window;
    return candidate;
}

}  // namespace

bool quic_version_known(std::uint32_t version) noexcept {
    TypeMapping m{};
    return type_mapping_for(version, m);
}

QuicPacket parse_quic(std::span<const std::uint8_t> datagram) noexcept {
    QuicPacket out;
    if (datagram.size() < 7) return out;

    const std::uint8_t first = datagram[0];
    out.first_byte = first;
    if ((first & 0x80u) == 0) {
        // Short header (1-RTT). We cannot read the version or any protected field and
        // there is nothing useful to do with it.
        out.valid = true;
        out.long_header = false;
        out.type = QuicPacketType::one_rtt;
        out.packet_end = datagram.size();
        return out;
    }
    out.long_header = true;
    out.fixed_bit = (first & 0x40u) != 0;
    if (!out.fixed_bit) return out;  // RFC 8999 forbids a zero fixed bit

    const std::uint32_t version = read_be32(datagram, 1);
    out.version = version;
    out.version_known = quic_version_known(version);

    if (version == 0) {
        // Version Negotiation packet: the "version" field is actually a list.
        out.valid = true;
        out.type = QuicPacketType::version_negotiation;
        out.packet_end = datagram.size();
        return out;
    }

    std::size_t o = 5;
    if (o >= datagram.size()) return out;
    const std::size_t dcid_len = datagram[o++];
    if (dcid_len > kQuicMaxConnectionId || dcid_len > datagram.size() - o) return out;
    out.dcid_offset = o;
    out.dcid_length = dcid_len;
    o += dcid_len;

    if (o >= datagram.size()) return out;
    const std::size_t scid_len = datagram[o++];
    if (scid_len > kQuicMaxConnectionId || scid_len > datagram.size() - o) return out;
    out.scid_offset = o;
    out.scid_length = scid_len;
    o += scid_len;

    const std::uint8_t type_bits = static_cast<std::uint8_t>((first >> 4) & 0x03u);
    out.type = out.version_known ? type_from_bits(version, type_bits) : QuicPacketType::unknown;

    if (out.type == QuicPacketType::unknown) return out;
    if (out.type == QuicPacketType::one_rtt) return out;

    if (out.type == QuicPacketType::retry || out.type == QuicPacketType::version_negotiation) {
        // Retry carries a token and an integrity tag, not a length field.
        out.valid = true;
        out.token_offset = o;
        out.token_length = datagram.size() - o;
        out.packet_end = datagram.size();
        return out;
    }

    // Initial / 0-RTT / Handshake share the "token length + length" tail for the
    // versions we support; 0-RTT and Handshake carry no token, but reading the token
    // length varint as zero is what RFC 9000 section 17.2 specifies for them too.
    std::uint64_t token_len = 0;
    std::size_t token_len_bytes = 0;
    if (!read_varint(datagram, o, token_len, token_len_bytes)) return out;
    if (token_len > datagram.size() - o) return out;
    out.token_offset = o;
    out.token_length = static_cast<std::size_t>(token_len);
    o += out.token_length;

    out.length_offset = o;
    std::uint64_t packet_len = 0;
    std::size_t length_bytes = 0;
    if (!read_varint(datagram, o, packet_len, length_bytes)) return out;
    out.length_field_size = length_bytes;
    out.length = packet_len;
    if (packet_len == 0) return out;
    // Length covers packet number + protected payload + 16-byte tag.
    if (packet_len > datagram.size() - o) return out;

    out.packet_number_offset = o;
    out.packet_end = o + static_cast<std::size_t>(packet_len);
    out.valid = true;
    return out;
}

std::optional<QuicInitialKeys> quic_initial_keys(std::uint32_t version,
                                                std::span<const std::uint8_t> dcid) noexcept {
    if (dcid.size() > kQuicMaxConnectionId) return std::nullopt;
    TypeMapping m{};
    if (!type_mapping_for(version, m)) return std::nullopt;

    const crypto::Bytes32 initial_secret =
        crypto::hkdf_extract(std::span<const std::uint8_t>(m.salt, 20), dcid);
    crypto::Bytes32 client_secret{};
    crypto::hkdf_expand_label(initial_secret, "client in", {}, client_secret);

    QuicInitialKeys keys;
    crypto::hkdf_expand_label(client_secret, m.key_label, {}, keys.key);
    crypto::hkdf_expand_label(client_secret, m.iv_label, {}, keys.iv);
    crypto::hkdf_expand_label(client_secret, m.hp_label, {}, keys.hp);
    return keys;
}

bool decrypt_quic_initial(std::span<const std::uint8_t> datagram, const QuicPacket& packet,
                          std::uint64_t largest_packet_number,
                          std::vector<std::uint8_t>& frames,
                          std::uint64_t& packet_number) noexcept {
    if (!packet.valid || packet.type != QuicPacketType::initial) return false;
    if (packet.packet_number_offset + 4 + 16 > packet.packet_end) return false;
    if (packet.packet_end > datagram.size()) return false;
    if (packet.length < 1 + 16) return false;

    const auto keys = quic_initial_keys(
        packet.version,
        datagram.subspan(packet.dcid_offset, packet.dcid_length));
    if (!keys.has_value()) return false;

    // Work on a copy so header protection removal never mutates the captured bytes.
    std::vector<std::uint8_t> work(datagram.begin(), datagram.end());
    std::span<std::uint8_t> w = std::span<std::uint8_t>(work).first(packet.packet_end);

    // --- header protection (RFC 9001 5.4.2) ---
    const std::size_t pn_offset = packet.packet_number_offset;
    if (pn_offset + 4 + 16 > w.size()) return false;
    const std::span<const std::uint8_t> sample(w.data() + pn_offset + 4, 16);
    const crypto::Aes128 hp_aes(keys->hp);
    std::array<std::uint8_t, 16> mask{};
    hp_aes.encrypt_block(sample, std::span<std::uint8_t>(mask));

    w[0] = static_cast<std::uint8_t>(w[0] ^ (mask[0] & 0x0fu));
    const std::size_t pn_len = static_cast<std::size_t>(w[0] & 0x03u) + 1u;
    if (pn_offset + pn_len > w.size()) return false;
    for (std::size_t i = 0; i < pn_len; ++i) {
        w[pn_offset + i] = static_cast<std::uint8_t>(w[pn_offset + i] ^ mask[1 + i]);
    }

    std::uint64_t truncated = 0;
    for (std::size_t i = 0; i < pn_len; ++i) {
        truncated = (truncated << 8) | w[pn_offset + i];
    }
    packet_number = reconstruct_packet_number(truncated, pn_len, largest_packet_number);

    // --- payload decryption (RFC 9001 5.3) ---
    const std::size_t ciphertext_begin = pn_offset + pn_len;
    const std::size_t ciphertext_len = w.size() - ciphertext_begin;
    if (ciphertext_len < 16) return false;

    // RFC 9001 5.3: the AEAD nonce is the IV with the packet number XOR-ed into its
    // rightmost 8 bytes. It is a XOR, not an assignment -- overwriting would destroy
    // the IV and every decryption would fail authentication.
    std::array<std::uint8_t, 12> nonce = keys->iv;
    for (std::size_t i = 0; i < 8; ++i) {
        nonce[11 - i] = static_cast<std::uint8_t>(
            nonce[11 - i] ^ static_cast<std::uint8_t>((packet_number >> (8u * i)) & 0xffu));
    }

    const std::span<const std::uint8_t> aad(w.data(), ciphertext_begin);
    const std::span<const std::uint8_t> ciphertext(w.data() + ciphertext_begin,
                                                   ciphertext_len - 16);
    const std::span<const std::uint8_t> tag(w.data() + ciphertext_begin + ciphertext_len - 16, 16);

    frames.resize(ciphertext.size());
    if (!crypto::aes128_gcm_decrypt(keys->key, nonce, aad, ciphertext, tag, frames)) {
        frames.clear();
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// CryptoStream
// ---------------------------------------------------------------------------

void CryptoStream::reset() noexcept {
    data_.clear();
    present_.clear();
    end_offset_ = 0;
    stored_ = 0;
    complete_ = false;
    connection_changed_ = false;
    version_ = 0;
    dcid_.clear();
}

void CryptoStream::adopt_connection(std::uint32_t version,
                                    std::span<const std::uint8_t> dcid) noexcept {
    if (version_ == version && dcid_ == std::vector<std::uint8_t>(dcid.begin(), dcid.end())) {
        return;
    }
    const bool first = version_ == 0 && dcid_.empty();
    version_ = version;
    dcid_.assign(dcid.begin(), dcid.end());
    if (first) return;
    // A Retry (or a new connection on the same 5-tuple) invalidates the old secret
    // stream: previously collected CRYPTO bytes can no longer be trusted.
    connection_changed_ = true;
    data_.clear();
    present_.clear();
    end_offset_ = 0;
    stored_ = 0;
    complete_ = false;
}

bool CryptoStream::add_frames(std::span<const std::uint8_t> frames) noexcept {
    if (complete_) return false;
    bool changed = false;
    std::size_t o = 0;
    while (o < frames.size()) {
        std::uint64_t frame_type = 0;
        std::size_t type_bytes = 0;
        if (!read_varint(frames, o, frame_type, type_bytes)) break;

        if (frame_type == 0x00) {  // PADDING
            continue;
        }
        if (frame_type == 0x01) {  // PING
            continue;
        }
        if (frame_type == 0x02 || frame_type == 0x03) {  // ACK / ACK_ECN
            std::uint64_t scratch = 0;
            std::size_t scratch_bytes = 0;
            if (!read_varint(frames, o, scratch, scratch_bytes)) break;  // largest_ack
            if (!read_varint(frames, o, scratch, scratch_bytes)) break;  // ack_delay
            std::uint64_t range_count = 0;
            if (!read_varint(frames, o, range_count, scratch_bytes)) break;
            if (range_count > 4096) break;  // refuse absurd ACK frames
            if (!read_varint(frames, o, scratch, scratch_bytes)) break;  // first_ack_range
            for (std::uint64_t i = 0; i < range_count; ++i) {
                if (!read_varint(frames, o, scratch, scratch_bytes)) return changed;  // gap
                if (!read_varint(frames, o, scratch, scratch_bytes)) return changed;  // length
            }
            if (frame_type == 0x03) {
                for (int i = 0; i < 3; ++i) {
                    if (!read_varint(frames, o, scratch, scratch_bytes)) return changed;
                }
            }
            continue;
        }
        if (frame_type == 0x06) {  // CRYPTO
            std::uint64_t offset = 0, length = 0;
            std::size_t dummy = 0;
            if (!read_varint(frames, o, offset, dummy)) break;
            if (!read_varint(frames, o, length, dummy)) break;
            if (offset > kMaxCryptoBytes || length > frames.size() - o) break;
            if (length == 0) continue;
            const std::size_t begin = static_cast<std::size_t>(offset);
            const std::size_t end = begin + static_cast<std::size_t>(length);
            if (end > kMaxCryptoBytes) {
                // The ClientHello we care about is far smaller; ignore the tail rather
                // than growing without bound.
                if (begin >= kMaxCryptoBytes) continue;
                length = kMaxCryptoBytes - begin;
            }
            if (data_.size() < end) {
                data_.resize(end, 0);
                present_.resize(end, false);
            }
            for (std::size_t i = 0; i < static_cast<std::size_t>(length); ++i) {
                if (!present_[begin + i]) {
                    data_[begin + i] = frames[o + i];
                    present_[begin + i] = true;
                    ++stored_;
                    changed = true;
                }
            }
            o += static_cast<std::size_t>(length);
            // Extend the contiguous prefix.
            while (end_offset_ < data_.size() && present_[end_offset_]) ++end_offset_;
            if (!complete_) {
                std::string ignored;
                if (client_hello_sni(ignored)) complete_ = true;
            }
            continue;
        }
        // CONNECTION_CLOSE / anything else: the handshake bytes we need are already in
        // front of us, so stop rather than guessing at frame layouts we do not model.
        break;
    }
    return changed;
}

bool CryptoStream::client_hello_sni(std::string& sni) const noexcept {
    if (end_offset_ < 4) return false;
    const std::span<const std::uint8_t> hs(data_.data(), end_offset_);
    if (hs[0] != 0x01) return false;  // not a ClientHello
    const std::size_t body_len = read_be24(hs, 1);
    if (body_len < 34 || body_len + 4 > end_offset_) return false;
    const TlsClientHello hello = parse_client_hello_body(hs.subspan(4, body_len));
    if (!hello.has_sni) return false;
    sni = hello.sni;
    return true;
}

// ---------------------------------------------------------------------------
// Decoy construction
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> build_quic_client_initial(std::string_view sni, std::size_t target_size,
                                                    std::uint32_t random_seed) noexcept {
    if (sni.empty() || !is_valid_hostname(sni)) return {};
    if (target_size < kQuicMinimumInitialSize) target_size = kQuicMinimumInitialSize;

    std::uint32_t rng = random_seed == 0 ? 0x243f6a88u : random_seed;

    // Connection IDs: a client-chosen DCID drives Initial key derivation.
    std::vector<std::uint8_t> dcid(8);
    std::vector<std::uint8_t> scid(8);
    for (std::uint8_t& b : dcid) b = static_cast<std::uint8_t>(xorshift32(rng) & 0xffu);
    for (std::uint8_t& b : scid) b = static_cast<std::uint8_t>(xorshift32(rng) & 0xffu);

    const auto keys = quic_initial_keys(kQuicV1, dcid);
    if (!keys.has_value()) return {};

    // TLS ClientHello -> CRYPTO frame payload.
    std::vector<std::uint8_t> hello(512);
    const std::size_t hello_len = build_client_hello(hello, sni, xorshift32(rng));
    if (hello_len == 0) return {};

    // Header: long header, fixed bit, Initial type (0b00 for v1), 4-byte packet number.
    // The Length varint width depends on the payload size, which in turn depends on the
    // width, so resolve it with a short fixed-point iteration.
    constexpr std::size_t pn_len = 4;
    constexpr std::size_t tag_len = 16;
    std::vector<std::uint8_t> header;
    // 1 (flags) + 4 (version) + 1 + 20 (dcid) + 1 + 20 (scid) + 9 (token length)
    // + 9 (length, worst case 8-byte varint) + 4 (packet number)
    header.reserve(70);
    // Reserve the first five bytes before writing the version into them: writing at an
    // offset that the vector has not been sized for is an out-of-bounds write.
    header.resize(5);
    header[0] = 0xc3;
    write_be32(header, 1, kQuicV1);
    header.push_back(static_cast<std::uint8_t>(dcid.size()));
    header.insert(header.end(), dcid.begin(), dcid.end());
    header.push_back(static_cast<std::uint8_t>(scid.size()));
    header.insert(header.end(), scid.begin(), scid.end());
    append_varint(header, 0);  // Token Length
    const std::size_t length_offset = header.size();

    std::size_t width = 2;
    std::size_t payload_len = 0;
    bool resolved = false;
    for (int attempt = 0; attempt < 4; ++attempt) {
        const std::size_t header_len = length_offset + width + pn_len;
        if (header_len + tag_len > target_size) return {};
        payload_len = target_size - header_len - tag_len;
        const std::size_t length_value = pn_len + payload_len + tag_len;
        const std::size_t needed = varint_size_for(length_value);
        if (needed == width) {
            resolved = true;
            break;
        }
        width = needed;
    }
    if (!resolved) return {};

    append_varint(header, pn_len + payload_len + tag_len);
    header.insert(header.end(), {0x00, 0x00, 0x00, 0x00});  // packet number 0

    // Frames: CRYPTO(offset 0) followed by PADDING up to the target size.
    // RFC 9001 section 4.1.4: QUIC CRYPTO frames carry the TLS *handshake message*;
    // the record layer is not used by QUIC, so the 5-byte record header that
    // build_client_hello() emits must be stripped here.
    constexpr std::size_t kTlsRecordHeaderLen = 5;
    if (hello_len <= kTlsRecordHeaderLen) return {};
    std::vector<std::uint8_t> payload;
    append_varint(payload, 0x06);
    append_varint(payload, 0);
    append_varint(payload, hello_len - kTlsRecordHeaderLen);
    payload.insert(payload.end(),
                   hello.begin() + static_cast<std::ptrdiff_t>(kTlsRecordHeaderLen),
                   hello.begin() + static_cast<std::ptrdiff_t>(hello_len));
    if (payload.size() > payload_len) return {};
    payload.resize(payload_len, 0x00);  // PADDING frames

    // Nonce: IV XOR packet number (packet number 0 here).
    std::array<std::uint8_t, 12> nonce = keys->iv;

    std::vector<std::uint8_t> packet = header;
    const std::size_t cipher_offset = packet.size();
    packet.resize(packet.size() + payload.size() + tag_len, 0);
    crypto::aes128_gcm_encrypt(
        keys->key, nonce, std::span<const std::uint8_t>(packet.data(), cipher_offset), payload,
        std::span<std::uint8_t>(packet).subspan(cipher_offset, payload.size()),
        std::span<std::uint8_t>(packet).last(tag_len));

    // Header protection (RFC 9001 5.4.1). The sample starts 4 bytes after the PN.
    const std::size_t pn_offset = cipher_offset - pn_len;
    const crypto::Aes128 hp_aes(keys->hp);
    std::array<std::uint8_t, 16> mask{};
    hp_aes.encrypt_block(std::span<const std::uint8_t>(packet.data() + pn_offset + 4, 16),
                         std::span<std::uint8_t>(mask));
    packet[0] = static_cast<std::uint8_t>(packet[0] ^ (mask[0] & 0x0fu));
    for (std::size_t i = 0; i < pn_len; ++i) {
        packet[pn_offset + i] = static_cast<std::uint8_t>(packet[pn_offset + i] ^ mask[1 + i]);
    }
    return packet;
}

}  // namespace zc
