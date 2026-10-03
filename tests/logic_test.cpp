#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "csum.hpp"
#include "desync.hpp"
#include "flow.hpp"
#include "http.hpp"
#include "quic.hpp"
#include "rules.hpp"
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

static void append_quic_varint(std::vector<std::uint8_t>& out, std::uint64_t v) {
    if (v <= 63) {
        out.push_back(static_cast<std::uint8_t>(v));
    } else if (v <= 16383) {
        out.push_back(static_cast<std::uint8_t>(0x40u | ((v >> 8) & 0x3fu)));
        out.push_back(static_cast<std::uint8_t>(v & 0xffu));
    }
}

static std::vector<std::uint8_t> build_quic_initial(std::uint32_t version, std::uint8_t first,
                                                     std::size_t payload_len) {
    std::vector<std::uint8_t> init;
    init.push_back(first);
    init.push_back(static_cast<std::uint8_t>((version >> 24) & 0xffu));
    init.push_back(static_cast<std::uint8_t>((version >> 16) & 0xffu));
    init.push_back(static_cast<std::uint8_t>((version >> 8) & 0xffu));
    init.push_back(static_cast<std::uint8_t>(version & 0xffu));
    init.push_back(0x08);
    for (int i = 0; i < 8; ++i) init.push_back(static_cast<std::uint8_t>(0x10 + i));
    init.push_back(0x00); // SCID length
    append_quic_varint(init, 0); // token length
    append_quic_varint(init, payload_len);
    for (std::size_t i = 0; i < payload_len; ++i) init.push_back(0xaa);
    return init;
}

static void test_quic_detection() {
    std::vector<std::uint8_t> init = build_quic_initial(0x00000001u, 0xc0, 68);
    zc::QuicInitial q = zc::parse_quic_initial(init.data(), init.size());
    check(q.valid, "quic v1 initial parsed");
    check(q.dcid_length == 8, "quic dcid length parsed");
    check(q.dcid_offset == 6, "quic dcid offset correct");
    check(q.length == 68 && q.length_field_size == 2, "quic varint length parsed");
    check(zc::is_quic_initial(init.data(), init.size()), "is_quic_initial agrees");

    std::vector<std::uint8_t> v2 = build_quic_initial(0x6b3343cfu, 0xd0, 32);
    zc::QuicInitial q2 = zc::parse_quic_initial(v2.data(), v2.size());
    check(q2.valid && q2.version == 0x6b3343cfu, "quic v2 initial parsed");

    std::vector<std::uint8_t> unknown = build_quic_initial(0x11223344u, 0xc0, 32);
    check(!zc::is_quic_initial(unknown.data(), unknown.size()), "unknown QUIC version is not guessed");

    std::uint8_t random[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    check(!zc::is_quic_initial(random, sizeof(random)), "non-quic udp rejected");

    std::uint8_t short_header[10] = {0x40, 0x11, 0x22, 0x33, 0x44, 0x55,
                                     0x66, 0x77, 0x88, 0x99};
    check(!zc::is_quic_initial(short_header, sizeof(short_header)), "quic 1-RTT short header rejected");

    std::vector<std::uint8_t> fake = zc::build_fake_quic_initial(1200, &q);
    check(fake.size() == 1200, "fake quic initial built to target size");
    check((fake[0] & 0x80) != 0 && ((fake[0] >> 4) & 0x03) == 0x00,
          "fake quic v1 has Initial type");
    check(fake[1] == 0x00 && fake[4] == 0x01, "fake quic version is v1");
    check(fake[5] == q.dcid_length, "fake quic reuses real dcid length");
    check(zc::parse_quic_initial(fake.data(), fake.size()).valid, "fake quic v1 is parseable");

    std::vector<std::uint8_t> fake2 = zc::build_fake_quic_initial(1200, &q2);
    check(((fake2[0] >> 4) & 0x03) == 0x01, "fake quic v2 has v2 Initial type");
    check(zc::parse_quic_initial(fake2.data(), fake2.size()).valid, "fake quic v2 is parseable");
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
    cap.seen_and_mark(f1, 1);
    cap.seen_and_mark(f2, 2);
    cap.seen_and_mark(f3, 3);
    check(cap.size() <= 2, "cache respects exact capacity bound");
    check(!cap.seen_and_mark(f1, 4), "oldest flow is evicted instead of clearing the cache");
    cap.forget(f1);
    check(!cap.seen_and_mark(f1, 5), "forgotten flow becomes new again");
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

static void test_tls_partial_and_fake_auto() {
    const std::string host = "very-long-example-domain.test";
    const std::vector<std::uint8_t> rec = build_client_hello(host);
    std::vector<std::uint8_t> partial(rec.begin(), rec.begin() + 20);
    const zc::TlsClientHello p = zc::parse_client_hello(partial.data(), partial.size());
    check(p.is_tls_handshake && p.is_client_hello && !p.complete && !p.valid,
          "partial ClientHello is recognized without inventing SNI");

    zc::Packet pkt;
    pkt.bytes = build_ipv4_tcp(0, rec);
    check(pkt.parse(), "TLS packet for fake-auto parses");
    const zc::TlsClientHello tls = zc::parse_client_hello(pkt.payload(), pkt.payload_len());
    zc::Config cfg;
    cfg.strategy = zc::Strategy::FakeAuto;
    cfg.repeats = 1;
    auto out = zc::apply_desync(pkt, tls, cfg);
    check(out.size() >= 3 && out.front().trick, "fake-auto emits a decoy plus real segments");
    if (!out.empty() && out.front().parse()) {
        const auto ftls = zc::parse_client_hello(out.front().payload(), out.front().payload_len());
        const std::string fake_host = zc::client_hello_sni(out.front().payload(), out.front().payload_len(), ftls);
        check(ftls.valid && fake_host.size() == host.size() && fake_host != host,
              "fake-auto keeps valid TLS framing and replaces SNI with same-length decoy");
    } else {
        check(false, "fake-auto decoy packet parses");
    }

    const std::string boundary_host = std::string(31, 'x') + "." + std::string(32, 'y');
    const auto boundary_rec = build_client_hello(boundary_host);
    zc::Packet boundary_pkt;
    boundary_pkt.bytes = build_ipv4_tcp(0, boundary_rec);
    check(boundary_pkt.parse(), "64-byte hostname packet parses");
    const auto boundary_tls = zc::parse_client_hello(boundary_pkt.payload(), boundary_pkt.payload_len());
    auto boundary_out = zc::apply_desync(boundary_pkt, boundary_tls, cfg);
    if (!boundary_out.empty() && boundary_out.front().parse()) {
        const auto fake_tls = zc::parse_client_hello(boundary_out.front().payload(), boundary_out.front().payload_len());
        check(fake_tls.valid && fake_tls.sni_length == boundary_host.size(),
              "exact-length fake hostname remains DNS-valid across 63-byte label boundary");
    } else {
        check(false, "64-byte fake-auto decoy packet parses");
    }
}

static void test_http_header_boundaries() {
    std::string req = "GET / HTTP/1.1\r\nX-Note: prefix host:evil.example\r\nHost: good.example\r\n\r\n";
    std::vector<std::uint8_t> b(req.begin(), req.end());
    const auto h = zc::parse_http_request(b.data(), b.size());
    check(h.valid && h.host == "good.example", "Host is matched only at a header boundary");

    std::string ipv6 = "CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n";
    std::vector<std::uint8_t> b6(ipv6.begin(), ipv6.end());
    const auto h6 = zc::parse_http_request(b6.data(), b6.size());
    check(h6.valid && h6.host == "2001:db8::1", "bracketed IPv6 HTTP authority is normalized");
}

static void test_service_specificity() {
    const zc::Service* gv = zc::find_service("r1---sn-x.googlevideo.com");
    check(gv != nullptr && std::string(gv->name) == "youtube", "googlevideo prefers YouTube profile");
    const zc::Service* dc = zc::find_service("cdn.discordapp.com");
    check(dc != nullptr && std::string(dc->name) == "discord-cdn", "discord CDN prefers specialized profile");
}

static void test_rules_and_domain_lists() {
    check(zc::domain_suffix_match("a.b.Example.COM.", "example.com"), "domain suffix matching is case-insensitive");
    check(!zc::domain_suffix_match("notexample.com", "example.com"), "domain suffix matching respects label boundaries");

    const auto tmp = std::filesystem::temp_directory_path() / "zapret_cpp_rules_test.txt";
    {
        std::ofstream f(tmp);
        f << "example.com disorder repeats=2\n";
        f << "video.example.com fake-auto ttl=7 repeats=4 badseq=1 rnd=1 fake-sni=www.cloudflare.com\n";
    }
    zc::RuleSet rules;
    std::string err;
    check(rules.load_file(tmp, &err), "rule file loads");
    const zc::DomainRule* r = rules.find("cdn.video.example.com");
    check(r != nullptr && r->suffix == "video.example.com", "longest matching domain rule wins");
    if (r != nullptr) {
        zc::Config cfg;
        zc::apply_rule(*r, cfg);
        check(cfg.strategy == zc::Strategy::FakeAuto && cfg.fake_ttl == 7 && cfg.repeats == 4 &&
              cfg.fooling_badseq && cfg.fake_mod_rnd, "domain rule options apply to config");
    }
    std::filesystem::remove(tmp);
}

static std::vector<std::uint8_t> build_ipv6_hop_tcp(const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> p(40, 0);
    p[0] = 0x60;
    const std::uint16_t pl = static_cast<std::uint16_t>(8 + 20 + payload.size());
    p[4] = static_cast<std::uint8_t>(pl >> 8);
    p[5] = static_cast<std::uint8_t>(pl & 0xffu);
    p[6] = 0; // Hop-by-Hop
    p[7] = 64;
    p[23] = 1;
    p[39] = 2;
    p.push_back(6); // TCP next header
    p.push_back(0); // 8-byte extension header
    for (int i = 0; i < 6; ++i) p.push_back(0);
    push16(p, 50000); push16(p, 443);
    p.insert(p.end(), {0,0,0,1, 0,0,0,1, 0x50,0x18});
    push16(p, 65535); push16(p, 0); push16(p, 0);
    p.insert(p.end(), payload.begin(), payload.end());
    return p;
}

static void test_ipv6_extension_headers() {
    zc::Packet p;
    p.bytes = build_ipv6_hop_tcp(std::vector<std::uint8_t>(10, 0x42));
    check(p.parse() && p.is_ipv6() && p.is_tcp() && p.l4_off() == 48 && p.payload_len() == 10,
          "IPv6 Hop-by-Hop extension chain reaches TCP payload");
    p.refresh_lengths_and_checksums();
    check(p.tcp() != nullptr && p.tcp()->checksum != 0, "IPv6 TCP checksum refresh works through extensions");
}

int main() {
    test_ipv4_checksum();
    test_tls_sni();
    test_tls_reject();
    test_tls_partial_and_fake_auto();
    test_service_matching();
    test_service_specificity();
    test_http_parsing();
    test_http_header_boundaries();
    test_quic_detection();
    test_flow_cache();
    test_rules_and_domain_lists();
    test_ip_fragments_rejected();
    test_ipv6_extension_headers();
    test_badseq_trick();

    if (g_fail == 0) {
        std::printf("\nall logic tests passed\n");
        return 0;
    }
    std::printf("\n%d test(s) failed\n", g_fail);
    return 1;
}
