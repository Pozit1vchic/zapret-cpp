#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "csum.hpp"
#include "desync.hpp"
#include "http.hpp"
#include "services.hpp"
#include "tls.hpp"

static int g_fail = 0;

static void check(bool cond, const char* msg) {
    if (cond) {
        std::printf("[ ok ] %s\n", msg);
    } else {
        std::printf("[FAIL] %s\n", msg);
        ++g_fail;
    }
}

static void push16(std::vector<std::uint8_t>& v, std::uint16_t x) {
    v.push_back(static_cast<std::uint8_t>(x >> 8));
    v.push_back(static_cast<std::uint8_t>(x & 0xff));
}

static std::vector<std::uint8_t> build_client_hello(const std::string& host) {
    std::vector<std::uint8_t> body;
    body.push_back(0x03);
    body.push_back(0x03);
    for (int i = 0; i < 32; ++i) {
        body.push_back(static_cast<std::uint8_t>(i));
    }
    body.push_back(0x00);
    push16(body, 2);
    push16(body, 0x1301);
    body.push_back(1);
    body.push_back(0x00);

    std::size_t ext_len_pos = body.size();
    push16(body, 0);
    std::size_t ext_start = body.size();

    push16(body, 0x0000);
    std::uint16_t sni_ext_len = static_cast<std::uint16_t>(2 + 1 + 2 + host.size());
    push16(body, sni_ext_len);
    push16(body, static_cast<std::uint16_t>(1 + 2 + host.size()));
    body.push_back(0x00);
    push16(body, static_cast<std::uint16_t>(host.size()));
    for (char c : host) {
        body.push_back(static_cast<std::uint8_t>(c));
    }

    std::uint16_t elen = static_cast<std::uint16_t>(body.size() - ext_start);
    body[ext_len_pos] = static_cast<std::uint8_t>(elen >> 8);
    body[ext_len_pos + 1] = static_cast<std::uint8_t>(elen & 0xff);

    std::vector<std::uint8_t> hs;
    hs.push_back(0x01);
    std::uint32_t hl = static_cast<std::uint32_t>(body.size());
    hs.push_back(static_cast<std::uint8_t>((hl >> 16) & 0xff));
    hs.push_back(static_cast<std::uint8_t>((hl >> 8) & 0xff));
    hs.push_back(static_cast<std::uint8_t>(hl & 0xff));
    hs.insert(hs.end(), body.begin(), body.end());

    std::vector<std::uint8_t> rec;
    rec.push_back(0x16);
    rec.push_back(0x03);
    rec.push_back(0x01);
    std::uint16_t rl = static_cast<std::uint16_t>(hs.size());
    rec.push_back(static_cast<std::uint8_t>(rl >> 8));
    rec.push_back(static_cast<std::uint8_t>(rl & 0xff));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

static std::size_t find_sub(const std::vector<std::uint8_t>& hay, const std::string& needle) {
    if (needle.empty() || hay.size() < needle.size()) {
        return std::string::npos;
    }
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        bool ok = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (hay[i + j] != static_cast<std::uint8_t>(needle[j])) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return i;
        }
    }
    return std::string::npos;
}

static void test_ipv4_checksum() {
    std::vector<std::uint8_t> hdr(20, 0);
    hdr[0] = 0x45;
    hdr[3] = 0x3c;
    hdr[8] = 64;
    hdr[9] = 6;
    hdr[12] = 192;
    hdr[13] = 168;
    hdr[14] = 1;
    hdr[15] = 1;
    hdr[16] = 192;
    hdr[17] = 168;
    hdr[18] = 1;
    hdr[19] = 2;

    std::uint16_t cs = zc::checksum16(hdr.data(), hdr.size());
    hdr[10] = static_cast<std::uint8_t>(cs >> 8);
    hdr[11] = static_cast<std::uint8_t>(cs & 0xff);
    std::uint32_t sum = zc::sum_bytes(hdr.data(), hdr.size(), 0);
    check(zc::fold_sum(sum) == 0x0000, "ipv4 header checksum verifies to zero");
}

static void test_tls_sni() {
    std::string host = "youtube.com";
    std::vector<std::uint8_t> rec = build_client_hello(host);

    zc::TlsClientHello tls = zc::parse_client_hello(rec.data(), rec.size());
    check(tls.valid, "client hello parsed");
    check(tls.sni_length == host.size(), "sni length matches");
    check(find_sub(rec, host) == tls.sni_offset, "sni offset matches hostname position");
}

static void test_tls_reject() {
    std::vector<std::uint8_t> junk(50, 0xaa);
    zc::TlsClientHello tls = zc::parse_client_hello(junk.data(), junk.size());
    check(!tls.valid, "non-tls data rejected");
}

static void test_service_matching() {
    check(zc::find_service("www.youtube.com") != nullptr, "youtube.com matched");
    check(zc::find_service("r1---sn-abc.googlevideo.com") != nullptr, "googlevideo subdomain matched");
    check(zc::find_service("cdn.discordapp.com") != nullptr, "discord cdn matched");
    check(zc::find_service("api.telegram.org") != nullptr, "telegram matched");
    check(zc::find_service("example.com") == nullptr, "unknown host not matched");
    check(zc::find_service("notyoutube.com.evil.com") == nullptr, "suffix spoof rejected");

    const zc::Service* yt = zc::find_service("www.youtube.com");
    check(yt != nullptr && std::string(yt->name) == "youtube", "youtube maps to youtube service");
}

static void test_http_parsing() {
    std::string req = "GET /index.html HTTP/1.1\r\nHost: www.youtube.com\r\nUser-Agent: x\r\n\r\n";
    std::vector<std::uint8_t> buf(req.begin(), req.end());
    zc::HttpRequest h = zc::parse_http_request(buf.data(), buf.size());
    check(h.valid, "http request parsed");
    check(h.host == "www.youtube.com", "http host extracted");

    std::string req2 = "POST /api HTTP/1.0\r\nhost:api.openai.com:443\r\n\r\n";
    std::vector<std::uint8_t> b2(req2.begin(), req2.end());
    zc::HttpRequest h2 = zc::parse_http_request(b2.data(), b2.size());
    check(h2.valid && h2.host == "api.openai.com", "lowercase host with port stripped");

    std::vector<std::uint8_t> junk(32, 0x41);
    zc::HttpRequest h3 = zc::parse_http_request(junk.data(), junk.size());
    check(!h3.valid, "non-http data rejected");
}

static void test_quic_detection() {
    std::uint8_t quic_initial[40] = {0};
    quic_initial[0] = 0xc0;
    quic_initial[1] = 0x00;
    quic_initial[2] = 0x00;
    quic_initial[3] = 0x00;
    quic_initial[4] = 0x01;
    check(zc::is_quic_initial(quic_initial, sizeof(quic_initial)), "quic long header detected");

    std::uint8_t quic_v2[8] = {0xc0, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x00, 0x00};
    check(zc::is_quic_initial(quic_v2, sizeof(quic_v2)), "quic v2 (draft) detected");

    std::uint8_t random[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    check(!zc::is_quic_initial(random, sizeof(random)), "non-quic udp rejected");
}

int main() {
    test_ipv4_checksum();
    test_tls_sni();
    test_tls_reject();
    test_service_matching();
    test_http_parsing();
    test_quic_detection();

    if (g_fail == 0) {
        std::printf("\nall logic tests passed\n");
        return 0;
    }
    std::printf("\n%d test(s) failed\n", g_fail);
    return 1;
}
