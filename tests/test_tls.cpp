// TLS record layer and ClientHello/SNI parsing.
#include <string>
#include <vector>

#include "packet_builder.hpp"
#include "test_util.hpp"
#include "zc/tls.hpp"

using namespace zctest;

namespace {

void check_happy_path() {
    const std::string host = "www.example.com";
    const auto record = build_client_hello(host);
    const zc::TlsClientHello hello = zc::parse_tls(record);
    ZC_CHECK(hello.is_tls);
    ZC_CHECK(hello.is_client_hello);
    ZC_CHECK(hello.record_complete);
    ZC_CHECK(hello.hello_complete);
    ZC_CHECK(hello.sni_present);
    ZC_CHECK(hello.has_sni);
    ZC_CHECK_EQ(hello.sni, host);
    ZC_CHECK_EQ(hello.sni_length, host.size());
    ZC_CHECK_EQ(hello.missing_bytes, 0u);
    ZC_CHECK(!hello.encrypted_client_hello);

    // The reported offsets must point at the actual hostname bytes.
    ZC_CHECK(std::string_view(reinterpret_cast<const char*>(record.data() + hello.sni_offset),
                              hello.sni_length) == host);
    ZC_CHECK_EQ(hello.cipher_suites_length, 4u);
    ZC_CHECK(hello.extensions_length > 0);
}

void check_case_normalization() {
    const auto record = build_client_hello("WWW.Example.COM");
    const zc::TlsClientHello hello = zc::parse_tls(record);
    ZC_CHECK(hello.has_sni);
    ZC_CHECK_EQ(hello.sni, std::string("www.example.com"));
    // Length must be preserved so an in-place decoy replacement stays valid.
    ZC_CHECK_EQ(hello.sni_length, std::string("WWW.Example.COM").size());
}

void check_trailing_dot() {
    const auto record = build_client_hello("example.com.");
    const zc::TlsClientHello hello = zc::parse_tls(record);
    ZC_CHECK(hello.has_sni);
    ZC_CHECK_EQ(hello.sni, std::string("example.com"));
}

void check_no_sni() {
    const auto record = build_client_hello("", false, false);
    const zc::TlsClientHello hello = zc::parse_tls(record);
    ZC_CHECK(hello.is_tls);
    ZC_CHECK(hello.is_client_hello);
    ZC_CHECK(hello.hello_complete);
    // No SNI extension at all: the engine must be able to tell "hostname unknown" apart
    // from "not TLS".
    ZC_CHECK(!hello.sni_present);
    ZC_CHECK(!hello.has_sni);
}

void check_invalid_sni_is_not_a_hostname() {
    // An SNI carrying bytes that are not a hostname must not become a rule key.
    std::vector<std::uint8_t> record = build_client_hello("example.com");
    const zc::TlsClientHello hello = zc::parse_tls(record);
    ZC_REQUIRE(hello.has_sni);
    record[hello.sni_offset] = ' ';  // a space cannot appear in a hostname
    const zc::TlsClientHello broken = zc::parse_tls(record);
    ZC_CHECK(broken.sni_present);
    ZC_CHECK(!broken.has_sni);
}

void check_ech() {
    std::vector<std::uint8_t> record = build_client_hello("example.com");
    // Append an encrypted_client_hello extension (0xfe0d) before the extension block end.
    const zc::TlsClientHello hello = zc::parse_tls(record);
    ZC_REQUIRE(hello.extensions_offset > 0);
    // Rebuild with the ECH extension appended after SNI. RFC 8446 / 9330 encrypted
    // ClientHello puts the public name in SNI and the real name inside an inner
    // ClientHello; the engine must notice that this hostname is not authoritative.
    std::vector<std::uint8_t> body;
    push16(body, 0x0303);
    for (int i = 0; i < 32; ++i) body.push_back(static_cast<std::uint8_t>(i));
    body.push_back(0);
    push16(body, 2);
    push16(body, 0x1301);
    body.push_back(1);
    body.push_back(0);
    const std::size_t ext_len_pos = body.size();
    push16(body, 0);
    const std::size_t ext_start = body.size();

    // server_name: list = name_type(1) + name_len(2) + "example"(7) = 10 bytes.
    push16(body, 0x0000);
    push16(body, 12);
    push16(body, 10);
    body.push_back(0);
    push16(body, 7);
    push_text(body, "example");
    // encrypted_client_hello
    push16(body, 0xfe0d);
    push16(body, 2);
    push16(body, 0x0001);

    const std::size_t ext_len = body.size() - ext_start;
    body[ext_len_pos] = static_cast<std::uint8_t>(ext_len >> 8);
    body[ext_len_pos + 1] = static_cast<std::uint8_t>(ext_len & 0xffu);

    std::vector<std::uint8_t> out;
    push8(out, 0x16);
    push8(out, 0x03);
    push8(out, 0x03);
    push16(out, static_cast<std::uint16_t>(body.size() + 4));
    push8(out, 0x01);
    push24(out, static_cast<std::uint32_t>(body.size()));
    out.insert(out.end(), body.begin(), body.end());

    const zc::TlsClientHello ech = zc::parse_tls(out);
    ZC_CHECK(ech.encrypted_client_hello);
    ZC_CHECK(ech.sni_present);
    ZC_CHECK(ech.has_sni);
    ZC_CHECK_EQ(ech.sni, std::string("example"));
}

void check_middlebox_compat_ccs() {
    // RFC 8446 D.4: a ChangeCipherSpec record may precede the ClientHello.
    std::vector<std::uint8_t> stream;
    push8(stream, 0x14);
    push8(stream, 0x03);
    push8(stream, 0x03);
    push16(stream, 1);
    push8(stream, 0x01);
    const auto record = build_client_hello("example.org");
    stream.insert(stream.end(), record.begin(), record.end());

    const zc::TlsClientHello hello = zc::parse_tls(stream);
    ZC_CHECK(hello.is_tls && hello.is_client_hello);
    ZC_CHECK(hello.has_sni);
    ZC_CHECK_EQ(hello.sni, std::string("example.org"));
    ZC_CHECK_EQ(hello.tls_offset, 6u);
}

void check_partial() {
    const auto record = build_client_hello("fragmented.example");
    for (std::size_t cut = 1; cut < record.size(); ++cut) {
        const zc::TlsClientHello hello =
            zc::parse_tls(std::span<const std::uint8_t>(record).first(cut));
        ZC_CHECK_MSG(!hello.has_sni,
                     "hostname must not be reported from only " + std::to_string(cut) +
                         " bytes");
        if (hello.is_tls) {
            ZC_CHECK_MSG(!hello.record_complete,
                         "record must not claim completeness at " + std::to_string(cut));
        }
    }
    const zc::TlsClientHello whole = zc::parse_tls(record);
    ZC_CHECK(whole.has_sni);
}

void check_record_spanning_multiple_segments() {
    // A ClientHello that continues into the "next segment" is still incomplete.
    const auto record = build_client_hello("spanning.example");
    const std::size_t cut = record.size() / 2;
    const zc::TlsClientHello first =
        zc::parse_tls(std::span<const std::uint8_t>(record).first(cut));
    ZC_CHECK(first.is_tls && first.is_client_hello);
    ZC_CHECK(!first.record_complete);
    ZC_CHECK(!first.hello_complete);
    ZC_CHECK(first.missing_bytes > 0);
    ZC_CHECK(!first.has_sni);
}

void check_non_tls() {
    const std::vector<std::uint8_t> nothing;
    ZC_CHECK(!zc::parse_tls(nothing).is_tls);
    const std::vector<std::uint8_t> single{0x16};
    ZC_CHECK(!zc::parse_tls(single).is_tls);
    const std::vector<std::uint8_t> junk(64, 0xaa);
    ZC_CHECK(!zc::parse_tls(junk).is_tls);
    // Application data record (0x17) is not a handshake.
    std::vector<std::uint8_t> app = {0x17, 0x03, 0x03, 0x00, 0x10};
    ZC_CHECK(!zc::parse_tls(app).is_tls);
    // An alert record.
    std::vector<std::uint8_t> alert = {0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00};
    ZC_CHECK(!zc::parse_tls(alert).is_tls);
    // Wrong major version.
    std::vector<std::uint8_t> bad_version = {0x16, 0x02, 0x00, 0x00, 0x05, 0x01, 0, 0, 0};
    ZC_CHECK(!zc::parse_tls(bad_version).is_tls);
}

void check_bad_lengths() {
    // TLSPlaintext.length must be non-zero and bounded.
    std::vector<std::uint8_t> zero_length = {0x16, 0x03, 0x01, 0x00, 0x00, 0x01};
    const zc::TlsClientHello zero = zc::parse_tls(zero_length);
    ZC_CHECK(!zero.is_client_hello);
    ZC_CHECK(!zero.has_sni);

    // An enormous length must be refused rather than trusted.
    std::vector<std::uint8_t> huge = {0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00};
    const zc::TlsClientHello big = zc::parse_tls(huge);
    ZC_CHECK(!big.is_client_hello);
    ZC_CHECK(!big.has_sni);

    // A handshake record whose declared length exceeds the buffer: incomplete, never SNI.
    std::vector<std::uint8_t> lying = {0x16, 0x03, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x40};
    const zc::TlsClientHello partial = zc::parse_tls(lying);
    ZC_CHECK(partial.is_client_hello);
    ZC_CHECK(!partial.record_complete);
    ZC_CHECK(!partial.has_sni);
}

void check_malformed_extensions() {
    // Extension length larger than the extension block.
    std::vector<std::uint8_t> record = build_client_hello("x.example");
    const zc::TlsClientHello hello = zc::parse_tls(record);
    ZC_REQUIRE(hello.extensions_offset > 0);
    auto broken = record;
    broken[hello.extensions_offset - 2] = 0xff;
    broken[hello.extensions_offset - 1] = 0xff;
    const zc::TlsClientHello bad = zc::parse_tls(broken);
    ZC_CHECK(!bad.has_sni);
    ZC_CHECK(!bad.hello_complete);

    // SNI list length larger than the extension.
    auto broken2 = record;
    const zc::TlsClientHello reference = zc::parse_tls(record);
    ZC_REQUIRE(reference.sni_offset > 0);
    broken2[reference.sni_offset - 4] = 0xff;
    broken2[reference.sni_offset - 3] = 0xff;
    ZC_CHECK(!zc::parse_tls(broken2).has_sni);
}

void check_hostname_validation() {
    ZC_CHECK(zc::is_valid_hostname("example.com"));
    ZC_CHECK(zc::is_valid_hostname("a.b.c.example.com"));
    ZC_CHECK(zc::is_valid_hostname("xn--bcher-kva.example"));
    ZC_CHECK(zc::is_valid_hostname("1example.com"));
    ZC_CHECK(!zc::is_valid_hostname(""));
    ZC_CHECK(!zc::is_valid_hostname("."));
    ZC_CHECK(!zc::is_valid_hostname("example..com"));
    ZC_CHECK(!zc::is_valid_hostname("-example.com"));
    ZC_CHECK(!zc::is_valid_hostname("example-.com"));
    ZC_CHECK(!zc::is_valid_hostname("exa mple.com"));
    ZC_CHECK(!zc::is_valid_hostname("under_score.example"));
    ZC_CHECK(!zc::is_valid_hostname(std::string(64, 'a').c_str()));
    ZC_CHECK(zc::is_valid_hostname(std::string(63, 'a') + ".example"));
    ZC_CHECK(!zc::is_valid_hostname(std::string(300, 'a')));
    ZC_CHECK(zc::normalize_hostname("EXAMPLE.com.").has_value());
    ZC_CHECK_EQ(*zc::normalize_hostname("EXAMPLE.com."), std::string("example.com"));
    ZC_CHECK(!zc::normalize_hostname("-bad-.com").has_value());
}

void check_fit_hostname() {
    // Exact length must always be achievable for representable lengths.
    for (std::size_t length : {4u, 8u, 15u, 16u, 17u, 32u, 63u, 64u, 100u, 128u, 200u}) {
        const auto fitted = zc::fit_hostname("www.google.com", length);
        ZC_CHECK_MSG(fitted.has_value(), "length " + std::to_string(length));
        if (fitted) {
            ZC_CHECK_MSG(fitted->size() == length, "size for " + std::to_string(length));
            ZC_CHECK_MSG(zc::is_valid_hostname(*fitted), "valid for " + std::to_string(length));
        }
    }
    // Every representable length must yield a valid name; beyond 253 bytes no
    // hostname can exist at all, so the call is refused rather than producing junk.
    for (std::size_t length = 1; length <= 253; ++length) {
        const auto fitted = zc::fit_hostname("www.google.com", length);
        if (!fitted || fitted->size() != length || !zc::is_valid_hostname(*fitted)) {
            ZC_CHECK_MSG(false, "length " + std::to_string(length) + " must be representable");
            break;
        }
    }
    for (std::size_t length : {254u, 255u, 300u, 1000u}) {
        ZC_CHECK_MSG(!zc::fit_hostname("www.google.com", length),
                     "length " + std::to_string(length) + " must be refused");
    }
    ZC_CHECK(!zc::fit_hostname("", 0));
    ZC_CHECK(!zc::fit_hostname("", 300));
}

void check_client_hello_builder() {
    std::vector<std::uint8_t> buffer(512);
    const std::size_t n = zc::build_client_hello(buffer, "built.example", 0x1234);
    ZC_REQUIRE(n > 0);
    const zc::TlsClientHello hello = zc::parse_tls(
        std::span<const std::uint8_t>(buffer.data(), n));
    ZC_CHECK(hello.is_tls && hello.is_client_hello && hello.hello_complete);
    ZC_CHECK(hello.has_sni);
    ZC_CHECK_EQ(hello.sni, std::string("built.example"));
    // The declared record length must match the bytes produced.
    ZC_CHECK_EQ(hello.record_length, n);
}

void check_handshake_body_parser() {
    const auto record = build_client_hello("body.example");
    // The body starts after the 5-byte record header and 4-byte handshake header.
    const std::span<const std::uint8_t> body(record.data() + 9, record.size() - 9);
    const zc::TlsClientHello hello = zc::parse_client_hello_body(body);
    ZC_CHECK(hello.has_sni);
    ZC_CHECK_EQ(hello.sni, std::string("body.example"));
    // Truncations must never produce an SNI.
    for (std::size_t cut = 1; cut < body.size(); ++cut) {
        const zc::TlsClientHello partial =
            zc::parse_client_hello_body(body.first(cut));
        ZC_CHECK_MSG(!partial.has_sni, "truncated body of " + std::to_string(cut));
    }
}

void run() {
    check_happy_path();
    check_case_normalization();
    check_trailing_dot();
    check_no_sni();
    check_invalid_sni_is_not_a_hostname();
    check_ech();
    check_middlebox_compat_ccs();
    check_partial();
    check_record_spanning_multiple_segments();
    check_non_tls();
    check_bad_lengths();
    check_malformed_extensions();
    check_hostname_validation();
    check_fit_hostname();
    check_client_hello_builder();
    check_handshake_body_parser();
}

}  // namespace

ZC_TEST_MAIN("tls", run)
