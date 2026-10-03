// HTTP/1.x request parsing.
#include <string>
#include <vector>

#include "packet_builder.hpp"
#include "test_util.hpp"
#include "zc/http.hpp"

using namespace zctest;

namespace {

zc::HttpRequest parse_text(std::string_view text) {
    const std::vector<std::uint8_t> data(text.begin(), text.end());
    return zc::parse_http(data);
}

void check_basic() {
    const auto h = parse_text("GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n"
                              "User-Agent: test\r\n\r\n");
    ZC_CHECK(h.status == zc::HttpRequest::Status::complete);
    ZC_CHECK(h.usable());
    ZC_CHECK_EQ(h.host, std::string("www.example.com"));
    ZC_CHECK(!h.host_is_ip);
    ZC_CHECK_EQ(h.method_length, 3u);
    ZC_CHECK(h.headers_end > h.request_line_end);
    ZC_CHECK_EQ(h.host_value_length, std::string("www.example.com").size());
}

void check_case_insensitive_header() {
    for (const char* name : {"Host", "host", "HOST", "hOsT"}) {
        std::string request = "GET / HTTP/1.1\r\n";
        request += name;
        request += ": example.com\r\n\r\n";
        const auto h = parse_text(request);
        ZC_CHECK_MSG(h.usable(), name);
        if (h.usable()) ZC_CHECK_EQ(h.host, std::string("example.com"));
    }
}

void check_port_and_brackets() {
    const auto with_port = parse_text("GET / HTTP/1.1\r\nHost: api.example.com:8443\r\n\r\n");
    ZC_CHECK(with_port.usable());
    ZC_CHECK_EQ(with_port.host, std::string("api.example.com"));
    ZC_CHECK_EQ(with_port.host_port, 8443);

    const auto ipv6 = parse_text("GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n");
    ZC_CHECK(ipv6.usable());
    ZC_CHECK_EQ(ipv6.host, std::string("2001:db8::1"));
    ZC_CHECK(ipv6.host_is_ip);
    ZC_CHECK_EQ(ipv6.host_port, 443);

    const auto bare_ipv6 = parse_text("GET / HTTP/1.1\r\nHost: 2001:db8::1\r\n\r\n");
    ZC_CHECK(bare_ipv6.usable());
    ZC_CHECK_EQ(bare_ipv6.host, std::string("2001:db8::1"));
    ZC_CHECK_EQ(bare_ipv6.host_port, 0);

    const auto ipv4 = parse_text("GET / HTTP/1.1\r\nHost: 93.184.216.34\r\n\r\n");
    ZC_CHECK(ipv4.usable());
    ZC_CHECK_EQ(ipv4.host, std::string("93.184.216.34"));
    ZC_CHECK(ipv4.host_is_ip);
}

void check_header_boundaries() {
    // "host:" inside another header value must not be mistaken for the Host header.
    const auto embedded = parse_text("GET / HTTP/1.1\r\nX-Note: prefix host:evil.example\r\n"
                                     "Host: good.example\r\n\r\n");
    ZC_CHECK(embedded.usable());
    ZC_CHECK_EQ(embedded.host, std::string("good.example"));

    // A header whose *name* starts with "host" is a different header.
    const auto prefixed = parse_text("GET / HTTP/1.1\r\nX-Host: evil.example\r\n"
                                     "Host: good.example\r\n\r\n");
    ZC_CHECK(prefixed.usable());
    ZC_CHECK_EQ(prefixed.host, std::string("good.example"));

    // "host" with no colon is not a header field.
    const auto no_colon = parse_text("GET / HTTP/1.1\r\nHost example.com\r\n\r\n");
    ZC_CHECK(!no_colon.usable());
    ZC_CHECK(no_colon.status == zc::HttpRequest::Status::malformed);
}

void check_no_host() {
    const auto h = parse_text("GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n");
    ZC_CHECK(h.status == zc::HttpRequest::Status::complete);
    ZC_CHECK(!h.usable());
    ZC_CHECK(!h.has_host);
}

void check_not_http() {
    ZC_CHECK(parse_text("").status == zc::HttpRequest::Status::not_http);
    ZC_CHECK(parse_text("G").status == zc::HttpRequest::Status::not_http);
    // A method-looking token with a non-HTTP version is some other protocol.
    ZC_CHECK(parse_text("GET / SMTP/2.0\r\n\r\n").status == zc::HttpRequest::Status::not_http);
    // Binary noise.
    ZC_CHECK(parse_text("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c").status ==
             zc::HttpRequest::Status::not_http);
    // Empty request target.
    ZC_CHECK(parse_text("GET  HTTP/1.1\r\nHost: x.example\r\n\r\n").status ==
             zc::HttpRequest::Status::not_http);
}

void check_versions() {
    ZC_CHECK(parse_text("GET / HTTP/1.0\r\nHost: x.example\r\n\r\n").usable());
    ZC_CHECK(parse_text("GET / HTTP/1.1\r\nHost: x.example\r\n\r\n").usable());
    ZC_CHECK(parse_text("GET / HTTP/2.0\r\nHost: x.example\r\n\r\n").status ==
             zc::HttpRequest::Status::not_http);
    ZC_CHECK(parse_text("GET / HTTP/9.9\r\nHost: x.example\r\n\r\n").status ==
             zc::HttpRequest::Status::not_http);
}

void check_methods() {
    for (const char* method : {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH",
                               "TRACE", "CONNECT"}) {
        std::string request = std::string(method) + " / HTTP/1.1\r\nHost: x.example\r\n\r\n";
        const auto h = parse_text(request);
        ZC_CHECK_MSG(h.usable(), method);
        if (h.usable()) ZC_CHECK_EQ(h.method_length, std::string(method).size());
    }
    // CONNECT to an authority form.
    ZC_CHECK(parse_text("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
                 .usable());
}

void check_partial() {
    // Truncated before the header block ends.
    for (const char* request : {
             "GET / HTTP/1.1\r\n",
             "GET / HTTP/1.1\r\nHost: example.com",
             "GET / HTTP/1.1\r\nHost: example.com\r\n",
             "GET / HTTP/1.1\r\nHost: example.com\r\nUser",
             "GET /",
             "GET / HTT",
         }) {
        const auto h = parse_text(request);
        // Either not HTTP yet or incomplete; never a usable request with a hostname we
        // could not actually see terminated.
        if (h.usable()) {
            ZC_CHECK_MSG(h.status == zc::HttpRequest::Status::complete, request);
            ZC_CHECK_MSG(h.headers_end <= std::string(request).size(), request);
        }
    }
    // A Host value cut in half must not be accepted.
    const auto cut = parse_text("GET / HTTP/1.1\r\nHost: exam");
    ZC_CHECK(!cut.usable());
}

void check_lone_cr() {
    // Some clients terminate lines with a bare LF.
    const auto lf = parse_text("GET / HTTP/1.1\nHost: example.com\n\n");
    ZC_CHECK(lf.usable());
    ZC_CHECK_EQ(lf.host, std::string("example.com"));

    // A bare CR inside the header block is tolerated.
    const auto cr = parse_text("GET / HTTP/1.1\rHost: example.com\r\r");
    ZC_CHECK(!cr.has_host || cr.host == "example.com");
}

void check_oversized() {
    std::string request = "GET / HTTP/1.1\r\nHost: example.com\r\n";
    for (int i = 0; i < 3000; ++i) request += "X-Filler: " + std::string(20, 'a') + "\r\n";
    request += "\r\n";
    ZC_CHECK(request.size() > zc::kMaxHttpHeaderBytes);
    const auto h = parse_text(request);
    // Either it is refused as too large, or it is complete but we never act on a
    // header block we had to guess about.
    ZC_CHECK(h.status == zc::HttpRequest::Status::too_large ||
             h.status == zc::HttpRequest::Status::complete);
    if (h.status == zc::HttpRequest::Status::complete) {
        ZC_CHECK(h.headers_end <= request.size());
    }
}

void check_invalid_host_values() {
    for (const char* value : {"", "   ", "bad host", "host<>name", "-leading.example",
                              "a..b", "under_score.example", "example.com:99999",
                              "example.com:abc"}) {
        std::string request = "GET / HTTP/1.1\r\nHost: ";
        request += value;
        request += "\r\n\r\n";
        const auto h = parse_text(request);
        ZC_CHECK_MSG(!h.has_host, value);
    }
    // Underscore is not a legal hostname character; it must not become a rule key.
    ZC_CHECK(!parse_text("GET / HTTP/1.1\r\nHost: a_b.example\r\n\r\n").has_host);
}

void check_whitespace() {
    const auto padded = parse_text("GET / HTTP/1.1\r\nHost:    example.com   \r\n\r\n");
    ZC_CHECK(padded.usable());
    ZC_CHECK_EQ(padded.host, std::string("example.com"));
    // Tab separated.
    const auto tabbed = parse_text("GET / HTTP/1.1\r\nHost:\texample.com\r\n\r\n");
    ZC_CHECK(tabbed.usable());
    ZC_CHECK_EQ(tabbed.host, std::string("example.com"));
}

void check_absolute_uri() {
    const auto h =
        parse_text("GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n");
    ZC_CHECK(h.usable());
    ZC_CHECK_EQ(h.host, std::string("example.com"));
}

void check_random() {
    // A large body of random bytes must almost never look like HTTP.
    Rng rng(0xc0ffee);
    int false_positives = 0;
    for (int i = 0; i < 20000; ++i) {
        std::vector<std::uint8_t> noise(8 + rng.below(200));
        rng.fill(noise);
        const auto h = zc::parse_http(noise);
        if (h.usable()) ++false_positives;
    }
    ZC_CHECK_MSG(false_positives == 0,
                 "random data produced " + std::to_string(false_positives) +
                     " usable HTTP requests (must be 0)");
}

void run() {
    check_basic();
    check_case_insensitive_header();
    check_port_and_brackets();
    check_header_boundaries();
    check_no_host();
    check_not_http();
    check_versions();
    check_methods();
    check_partial();
    check_lone_cr();
    check_oversized();
    check_invalid_host_values();
    check_whitespace();
    check_absolute_uri();
    check_random();
}

}  // namespace

ZC_TEST_MAIN("http", run)
