#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "csum.hpp"
#include "desync.hpp"
#include "flow.hpp"
#include "http.hpp"
#include "quic.hpp"
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

static std::vector<std::uint8_t> build_ipv4_tcp(std::uint16_t frag_off,
                                                const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> p;
    p.push_back(0x45);
    p.push_back(0);
    push16(p, static_cast<std::uint16_t>(20 + 20 + payload.size()));
    push16(p, 0x1234);
    push16(p, frag_off);
    p.push_back(64);
    p.push_back(6);
    push16(p, 0);
    p.insert(p.end(), {192, 168, 1, 1});
    p.insert(p.end(), {93, 184, 216, 34});
    push16(p, 50000);
    push16(p, 443);
    p.push_back(0); p.push_back(0); p.push_back(0); p.push_back(0x64);
    p.push_back(0); p.push_back(0); p.push_back(0); p.push_back(1);
    p.push_back(0x50); p.push_back(0x18);
    push16(p, 65535);
    push16(p, 0);
    push16(p, 0);
    p.insert(p.end(), payload.begin(), payload.end());
    return p;
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

    std::string no_host = "GET / HTTP/1.1\r\nX-Foo: bar\r\n\r\n";
    std::vector<std::uint8_t> b4(no_host.begin(), no_host.end());
    zc::HttpRequest h4 = zc::parse_http_request(b4.data(), b4.size());
    check(!h4.valid, "request without Host header rejected");

    std::string exact = "GET / HTTP/1.1\r\nHost: a.b";
    std::vector<std::uint8_t> b5(exact.begin(), exact.end());
    zc::HttpRequest h5 = zc::parse_http_request(b5.data(), b5.size());
    check(h5.valid && h5.host == "a.b", "host at end of buffer without CRLF parsed");

    std::string trailing_cr = "GET / HTTP/1.1\r\nHost: a.b\r";
    std::vector<std::uint8_t> b6(trailing_cr.begin(), trailing_cr.end());
    zc::HttpRequest h6 = zc::parse_http_request(b6.data(), b6.size());
    check(h6.valid && h6.host == "a.b", "host terminated by lone CR parsed");
}

static void test_quic_detection() {
    std::vector<std::uint8_t> init;
    init.push_back(0xc0);
    init.push_back(0x00);
    init.push_back(0x00);
    init.push_back(0x00);
    init.push_back(0x01);
    init.push_back(0x08);
    for (int i = 0; i < 8; ++i) {
        init.push_back(static_cast<std::uint8_t>(0x10 + i));
    }
    init.push_back(0x00);
    init.push_back(0x00);
    init.push_back(0x00);
    init.push_back(0x44);
    for (int i = 0; i < 32; ++i) {
        init.push_back(0xaa);
    }

    zc::QuicInitial q = zc::parse_quic_initial(init.data(), init.size());
    check(q.valid, "quic initial parsed");
    check(q.dcid_length == 8, "quic dcid length parsed");
    check(q.dcid_offset == 6, "quic dcid offset correct");
    check(q.length == 0x44, "quic length field parsed");
    check(zc::is_quic_initial(init.data(), init.size()), "is_quic_initial agrees");

    std::uint8_t random[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    check(!zc::is_quic_initial(random, sizeof(random)), "non-quic udp rejected");

    std::uint8_t short_header[10] = {0x40, 0x11, 0x22, 0x33, 0x44, 0x55,
                                     0x66, 0x77, 0x88, 0x99};
    check(!zc::is_quic_initial(short_header, sizeof(short_header)),
          "quic 1-RTT short header rejected");

    std::vector<std::uint8_t> fake = zc::build_fake_quic_initial(1200, &q);
    check(fake.size() == 1200, "fake quic initial built to target size");
    check((fake[0] & 0x80) != 0 && ((fake[0] >> 4) & 0x03) == 0x00,
          "fake quic initial is a long-header Initial");
    check(fake[1] == 0x00 && fake[4] == 0x01, "fake quic version is v1");
    check(fake[5] == q.dcid_length, "fake quic reuses real dcid length");
    check(zc::parse_quic_initial(fake.data(), fake.size()).valid,
          "fake quic initial is itself parseable");
}

static void test_flow_cache() {
    zc::FlowCache cache(4);
    zc::FlowKey a;
    a.src[15] = 1;
    a.dst[15] = 2;
    a.sport = 50000;
    a.dport = 443;
    a.proto = 6;

    check(!cache.seen_and_mark(a, 1000), "first packet of a flow is new");
    check(cache.seen_and_mark(a, 1001), "second packet of same flow is known");

    zc::FlowKey b = a;
    b.sport = 50001;
    check(!cache.seen_and_mark(b, 1002), "different source port is a new flow");

    zc::FlowKey c = a;
    c.dst[15] = 3;
    check(!cache.seen_and_mark(c, 1003), "different destination is a new flow");

    zc::FlowKey d = a;
    d.src[0] = 0xab;
    check(!cache.seen_and_mark(d, 1004), "differing high ipv6 bytes are a new flow");

    zc::FlowCache cap(2);
    zc::FlowKey f1;
    f1.sport = 1;
    zc::FlowKey f2;
    f2.sport = 2;
    zc::FlowKey f3;
    f3.sport = 3;
    cap.seen_and_mark(f1, 0);
    cap.seen_and_mark(f2, 0);
    cap.seen_and_mark(f3, 0);
    check(cap.size() <= 4, "cache respects capacity bound");
}

static void test_ip_fragments_rejected() {
    std::vector<std::uint8_t> payload(40, 0x41);

    zc::Packet plain;
    plain.bytes = build_ipv4_tcp(0x0000, payload);
    check(plain.parse() && plain.is_tcp(), "unfragmented packet parses");

    zc::Packet first;
    first.bytes = build_ipv4_tcp(0x2000, payload);
    check(!first.parse(), "first fragment (MF set) rejected");

    zc::Packet later;
    later.bytes = build_ipv4_tcp(0x0001, payload);
    check(!later.parse(), "non-zero fragment offset rejected");

    zc::Packet df;
    df.bytes = build_ipv4_tcp(0x4000, payload);
    check(df.parse() && df.is_tcp(), "DF-only packet still accepted");
}

static void test_badseq_trick() {
    std::vector<std::uint8_t> payload(40, 0x42);
    zc::Packet pkt;
    pkt.bytes = build_ipv4_tcp(0x0000, payload);
    pkt.parse();

    zc::TlsClientHello tls;
    zc::Config cfg;
    cfg.split_pos = 10;

    cfg.strategy = zc::Strategy::Disorder;
    cfg.fooling_badseq = true;
    cfg.repeats = 1;
    auto out = zc::apply_desync(pkt, tls, cfg);
    check(out.size() == 3, "disorder+badseq adds a trick packet");
    check(out[0].trick, "badseq trick packet is marked trick");
    check(!out[1].trick && !out[2].trick, "real segments are not trick packets");

    cfg.fooling_badseq = false;
    out = zc::apply_desync(pkt, tls, cfg);
    check(out.size() == 2, "disorder without badseq has just two segments");

    cfg.strategy = zc::Strategy::FakeMultidisorder;
    cfg.repeats = 3;
    cfg.fooling_badseq = true;
    out = zc::apply_desync(pkt, tls, cfg);
    int tricks = 0;
    int reals = 0;
    for (const auto& p : out) {
        if (p.trick) {
            ++tricks;
        } else {
            ++reals;
        }
    }
    check(tricks == 3, "repeats apply to the trick packet");
    check(reals >= 2, "real segments are not duplicated by repeats");
}

int main() {
    test_ipv4_checksum();
    test_tls_sni();
    test_tls_reject();
    test_service_matching();
    test_http_parsing();
    test_quic_detection();
    test_flow_cache();
    test_ip_fragments_rejected();
    test_badseq_trick();

    if (g_fail == 0) {
        std::printf("\nall logic tests passed\n");
        return 0;
    }
    std::printf("\n%d test(s) failed\n", g_fail);
    return 1;
}
