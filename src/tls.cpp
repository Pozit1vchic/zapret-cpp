#include "zc/tls.hpp"

#include <algorithm>
#include <array>
#include <cctype>

#include "zc/packet.hpp"

namespace zc {
namespace {

constexpr std::uint16_t kExtServerName = 0x0000;
constexpr std::uint16_t kExtEncryptedClientHello = 0xfe0d;
constexpr std::uint8_t kSniTypeHostName = 0x00;

bool record_version_ok(std::uint8_t major, std::uint8_t minor) noexcept {
    // TLS 1.0..1.3 use 0x03xx. SSL 3.0 (0x0300) still appears in the wild as a
    // legacy_record_version. Anything else is not a TLS record header we trust.
    return major == 0x03 && minor <= 0x04;
}

// Returns true when [off, off+need) lies inside [0, end).
inline bool have(std::size_t off, std::size_t need, std::size_t end) noexcept {
    return off <= end && need <= end - off;
}

}  // namespace

// Walk a ClientHello handshake body. Returns false when the body is malformed or
// truncated; in that case `out.hello_complete` is cleared, which is what tells the engine
// "we do not understand this ClientHello" instead of "we do not have it yet".
static bool walk_client_hello_body(std::span<const std::uint8_t> data, TlsClientHello& out) {
    std::size_t p = 0;
    const std::size_t end = data.size();

    // legacy_version(2) + random(32)
    if (!have(p, 34, end)) return false;
    out.legacy_version = read_be16(data, p);
    p += 34;

    // legacy_session_id
    if (!have(p, 1, end)) return false;
    const std::size_t sid_len = data[p++];
    if (!have(p, sid_len, end)) return false;
    out.session_id_length = static_cast<std::uint8_t>(sid_len);
    p += sid_len;

    // cipher_suites
    if (!have(p, 2, end)) return false;
    const std::size_t cs_len = read_be16(data, p);
    p += 2;
    if (cs_len < 2 || (cs_len % 2) != 0 || !have(p, cs_len, end)) return false;
    out.cipher_suites_offset = p;
    out.cipher_suites_length = cs_len;
    p += cs_len;

    // legacy_compression_methods
    if (!have(p, 1, end)) return false;
    const std::size_t comp_len = data[p++];
    if (comp_len == 0 || !have(p, comp_len, end)) return false;
    p += comp_len;

    // The extensions block is optional: TLS 1.0/1.1 ClientHellos end after the
    // compression methods and simply have no extensions.
    if (p == end) return true;
    if (!have(p, 2, end)) return false;
    const std::size_t ext_len = read_be16(data, p);
    p += 2;
    if (!have(p, ext_len, end)) return false;
    out.extensions_offset = p;
    out.extensions_length = ext_len;
    const std::size_t ext_end = p + ext_len;

    while (have(p, 4, ext_end)) {
        const std::uint16_t type = read_be16(data, p);
        const std::size_t elen = read_be16(data, p + 2);
        p += 4;
        if (!have(p, elen, ext_end)) return false;

        if (type == kExtServerName && elen >= 2) {
            const std::size_t list_len = read_be16(data, p);
            if (list_len > elen - 2) return false;
            std::size_t q = p + 2;
            const std::size_t q_end = q + list_len;
            while (have(q, 3, q_end)) {
                const std::uint8_t name_type = data[q];
                const std::size_t name_len = read_be16(data, q + 1);
                q += 3;
                if (!have(q, name_len, q_end)) return false;
                if (name_type == kSniTypeHostName && name_len > 0 && !out.sni_present) {
                    out.sni_offset = q;
                    out.sni_length = name_len;
                    out.sni_present = true;
                    const std::string_view raw(
                        reinterpret_cast<const char*>(data.data() + q), name_len);
                    if (auto host = normalize_hostname(raw)) {
                        out.sni = std::move(*host);
                        out.has_sni = true;
                    }
                    // Keep walking: encrypted_client_hello may appear after SNI and the
                    // caller needs to know the hostname is not the only identifier. A
                    // syntactically invalid SNI leaves sni_present true with has_sni
                    // false, so it can never become a rule key.
                }
                q += name_len;
            }
        } else if (type == kExtEncryptedClientHello) {
            out.encrypted_client_hello = true;
        }
        p += elen;
    }
    return true;
}

TlsClientHello parse_client_hello_body(std::span<const std::uint8_t> data) noexcept {
    TlsClientHello out;
    out.is_tls = true;
    out.is_client_hello = true;
    out.record_complete = true;
    out.hello_body_offset = 0;
    out.hello_body_length = data.size();
    out.hello_complete = walk_client_hello_body(data, out);
    if (!out.hello_complete) {
        out.sni.clear();
        out.has_sni = false;
        out.sni_present = false;
        out.encrypted_client_hello = false;
    }
    return out;
}

TlsClientHello parse_tls(std::span<const std::uint8_t> data) noexcept {
    TlsClientHello out;
    if (data.size() < 5) return out;

    std::size_t o = 0;
    for (std::size_t skip = 0; skip < kMaxTlsPrefixRecords; ++skip) {
        if (!have(o, 5, data.size())) return out;  // not enough for a record header

        const std::uint8_t content = data[o];
        const std::uint8_t major = data[o + 1];
        const std::uint8_t minor = data[o + 2];
        const std::size_t body_len = read_be16(data, o + 3);

        if (!record_version_ok(major, minor)) return out;

        // RFC 8446 Appendix D.4 middlebox-compatibility mode: a client may prefix the
        // ClientHello with a single dummy ChangeCipherSpec record. Skip those.
        if (content == static_cast<std::uint8_t>(TlsContentType::change_cipher_spec)) {
            if (body_len != 1) return out;
            if (!have(o, 6, data.size())) {
                out.is_tls = true;
                return out;
            }
            o += 6;
            continue;
        }

        if (content != static_cast<std::uint8_t>(TlsContentType::handshake)) return out;
        if (body_len == 0 || body_len > kMaxTlsRecordBody) {
            // Plausible TLS framing with an impossible length: not something we act on.
            return out;
        }

        out.is_tls = true;
        out.tls_offset = o;
        out.record_length = 5 + body_len;
        out.record_version = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(major) << 8) | static_cast<std::uint16_t>(minor));
        const bool record_fits = have(o, out.record_length, data.size());
        out.record_complete = record_fits;

        // Handshake message header inside the record.
        if (!have(o + 5, 4, data.size())) return out;
        const std::uint8_t handshake_type = data[o + 5];
        const std::size_t hs_body = read_be24(data, o + 6);
        if (handshake_type != 0x01) return out;  // TLS, but not a ClientHello

        out.is_client_hello = true;
        const std::size_t body_start = o + 9;
        const std::size_t hello_end = body_start + hs_body;
        out.hello_body_offset = body_start;
        out.hello_body_length = hs_body;
        out.hello_complete = record_fits && hello_end <= o + out.record_length &&
                             hello_end <= data.size();

        const std::size_t avail_end =
            record_fits ? std::min(o + out.record_length, data.size()) : data.size();
        const std::size_t limit = std::min(hello_end, avail_end);
        if (limit <= body_start) {
            // Only the handshake header arrived. We know it is a ClientHello but we do
            // not have it, so no hostname may be reported.
            out.hello_complete = false;
            if (hello_end > data.size()) out.missing_bytes = hello_end - data.size();
            return out;
        }

        TlsClientHello body =
            parse_client_hello_body(data.subspan(body_start, limit - body_start));
        body.is_tls = true;
        body.is_client_hello = true;
        body.record_complete = record_fits;
        // A ClientHello is only complete when it is fully present *and* fully
        // understood; walk_client_hello_body clears the flag on malformed input.
        body.hello_complete = out.hello_complete && body.hello_complete;
        body.tls_offset = o;
        body.record_length = out.record_length;
        body.record_version = out.record_version;
        body.hello_body_offset = body_start;
        body.hello_body_length = hs_body;
        body.missing_bytes = 0;
        // Shift offsets that were relative to the body slice back into the input span.
        body.extensions_offset += body_start;
        body.sni_offset += body_start;
        body.cipher_suites_offset += body_start;
        if (!out.hello_complete) {
            body.missing_bytes = hello_end > data.size() ? hello_end - data.size()
                                                         : hello_end - (o + out.record_length);
        }
        return body;
    }
    return out;
}

std::size_t build_client_hello(std::span<std::uint8_t> out, std::string_view sni,
                               std::uint32_t random_seed) noexcept {
    // 9 bytes of record + handshake header, then 34 fixed ClientHello bytes, one
    // session-id length byte, 2+6 cipher suites, 2 compression bytes, 2 extension
    // length bytes and ~60 bytes of extensions.
    if (sni.empty() || sni.size() > 253 || out.size() < 128 + sni.size()) return 0;

    // Extensions: SNI (0x0000), supported_versions (0x002b), supported_groups (0x000a),
    // signature_algorithms (0x000d) and ALPN (0x0010). key_share is intentionally
    // omitted to keep the message small; a decoy only has to be plausible.
    std::span<std::uint8_t> body = out.subspan(9);  // 5 record + 4 handshake header
    std::size_t body_pos = 0;

    auto put16 = [](std::span<std::uint8_t> d, std::size_t off, std::uint16_t v) {
        d[off] = static_cast<std::uint8_t>(v >> 8);
        d[off + 1] = static_cast<std::uint8_t>(v & 0xffu);
    };
    auto push16 = [&](std::uint16_t v) {
        body[body_pos++] = static_cast<std::uint8_t>(v >> 8);
        body[body_pos++] = static_cast<std::uint8_t>(v & 0xffu);
    };

    // legacy_version = TLS 1.2, random
    push16(0x0303);
    std::uint32_t rng = random_seed == 0 ? 0x9e3779b9u : random_seed;
    for (int i = 0; i < 32; ++i) {
        rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
        body[body_pos++] = static_cast<std::uint8_t>(rng & 0xffu);
    }
    // legacy_session_id (empty)
    body[body_pos++] = 0x00;
    // cipher_suites: TLS 1.3 AES-128-GCM, TLS 1.3 AES-256-GCM, TLS 1.3 CHACHA20
    body[body_pos++] = 0x00;
    body[body_pos++] = 0x06;
    for (const std::uint16_t suite : {std::uint16_t{0x1301}, std::uint16_t{0x1302}, std::uint16_t{0x1303}}) push16(suite);
    // legacy_compression_methods
    body[body_pos++] = 0x01;
    body[body_pos++] = 0x00;

    const std::size_t ext_len_pos = body_pos;
    push16(0);
    const std::size_t ext_start = body_pos;

    // server_name
    push16(0x0000);
    push16(static_cast<std::uint16_t>(5 + sni.size()));
    push16(static_cast<std::uint16_t>(3 + sni.size()));
    body[body_pos++] = 0x00;
    push16(static_cast<std::uint16_t>(sni.size()));
    for (char c : sni) body[body_pos++] = static_cast<std::uint8_t>(c);

    // supported_versions: TLS 1.3, TLS 1.2
    push16(0x002b);
    push16(5);
    body[body_pos++] = 4;
    body[body_pos++] = 0x03;
    body[body_pos++] = 0x04;
    body[body_pos++] = 0x03;
    body[body_pos++] = 0x03;

    // supported_groups
    push16(0x000a);
    push16(6);
    push16(4);
    push16(0x001d);  // x25519
    push16(0x0017);  // secp256r1

    // signature_algorithms: a 2-byte vector length followed by four 2-byte algorithms.
    push16(std::uint16_t{0x000d});
    push16(10);
    for (const std::uint16_t alg : {std::uint16_t{0x0403}, std::uint16_t{0x0804},
                                   std::uint16_t{0x0401}, std::uint16_t{0x0503}}) {
        push16(alg);
    }

    // ALPN (RFC 7301): extension length, protocol name list length, name length, "h2".
    push16(std::uint16_t{0x0010});
    push16(5);
    push16(3);
    body[body_pos++] = 2;
    body[body_pos++] = 'h';
    body[body_pos++] = '2';

    const std::size_t ext_len = body_pos - ext_start;
    put16(body, ext_len_pos, static_cast<std::uint16_t>(ext_len));

    const std::size_t hs_body = body_pos;
    const std::size_t total = 9 + hs_body;
    if (total > out.size() || hs_body > 0xffffffu) return 0;

    // Record header (handshake, TLS 1.0 legacy version for maximal compatibility)
    out[0] = static_cast<std::uint8_t>(TlsContentType::handshake);
    out[1] = 0x03;
    out[2] = 0x01;
    put16(out, 3, static_cast<std::uint16_t>(hs_body + 4));
    // Handshake header: client_hello + 24-bit length
    out[5] = 0x01;
    out[6] = static_cast<std::uint8_t>((hs_body >> 16) & 0xffu);
    out[7] = static_cast<std::uint8_t>((hs_body >> 8) & 0xffu);
    out[8] = static_cast<std::uint8_t>(hs_body & 0xffu);
    return total;
}

// ---------------------------------------------------------------------------
// hostname helpers
// ---------------------------------------------------------------------------

bool is_valid_hostname(std::string_view host) noexcept {
    if (host.empty() || host.size() > 253) return false;
    if (host.front() == '.' || host.back() == '.') return false;
    if (host.find("..") != std::string_view::npos) return false;

    std::size_t label_len = 0;
    for (std::size_t i = 0; i < host.size(); ++i) {
        const auto c = static_cast<unsigned char>(host[i]);
        if (c == '.') {
            if (label_len == 0 || label_len > 63) return false;
            label_len = 0;
            continue;
        }
        const bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                           (c >= '0' && c <= '9');
        // Only letters, digits and interior hyphens: an underscore is not a legal
        // hostname character and accepting it would create a rule key nothing can match.
        if (!alnum && c != '-') return false;
        if (label_len == 0 && c == '-') return false;
        if (label_len >= 63) return false;
        ++label_len;
        if (c == '-' && (i + 1 == host.size() || host[i + 1] == '.')) return false;
    }
    return label_len > 0 && label_len <= 63;
}

std::optional<std::string> normalize_hostname(std::string_view host) noexcept {
    if (!host.empty() && host.back() == '.') host.remove_suffix(1);
    if (!is_valid_hostname(host)) return std::nullopt;
    std::string out(host);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

std::optional<std::string> fit_hostname(std::string_view suffix, std::size_t target_len) noexcept {
    if (target_len == 0 || target_len > 253) return std::nullopt;

    std::string seed;
    if (auto s = normalize_hostname(suffix)) {
        seed = std::move(*s);
    } else {
        seed = "www.google.com";
    }
    if (seed.size() == target_len) return seed;

    // Try to keep the recognisable decoy as a suffix and pad with valid labels in
    // front. Padding is only possible when the seed fits inside k-1 labels.
    if (target_len > seed.size() + 1) {
        const std::size_t prefix_len = target_len - seed.size() - 1;
        // Prefix of `prefix_len` bytes must itself be a valid host. Build it as
        // labels of 'a' with the last label carrying the remainder.
        const std::size_t labels = (prefix_len + 63) / 64;
        if (labels >= 1 && prefix_len >= 2 * labels - 1) {
            std::size_t chars = prefix_len - (labels - 1);
            std::string prefix;
            prefix.reserve(prefix_len);
            for (std::size_t i = 0; i < labels; ++i) {
                const std::size_t left = labels - i;
                const std::size_t take = std::min<std::size_t>(63, chars - (left - 1));
                if (i != 0) prefix.push_back('.');
                prefix.append(take, 'a');
                chars -= take;
            }
            std::string candidate;
            candidate.reserve(target_len);
            candidate.append(prefix);
            candidate.push_back('.');
            candidate.append(seed);
            if (candidate.size() == target_len && is_valid_hostname(candidate)) {
                return candidate;
            }
        }
    }

    // Fall back to a generic exact-length name. With k labels the maximum length is
    // 64*k-1, so a length above that is simply not representable.
    const std::size_t labels = (target_len + 63) / 64;
    if (labels == 0 || target_len < 2 * labels - 1) return std::nullopt;
    std::size_t chars = target_len - (labels - 1);
    std::string out;
    out.reserve(target_len);
    for (std::size_t i = 0; i < labels; ++i) {
        const std::size_t left = labels - i;
        const std::size_t take = std::min<std::size_t>(63, chars - (left - 1));
        if (i != 0) out.push_back('.');
        out.append(take, 'a');
        chars -= take;
    }
    if (out.size() != target_len || !is_valid_hostname(out)) return std::nullopt;
    return out;
}

}  // namespace zc
