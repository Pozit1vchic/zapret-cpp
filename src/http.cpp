#include "zc/http.hpp"

#include <array>
#include <cctype>
#include <string_view>

#include "zc/packet.hpp"
#include "zc/tls.hpp"

namespace zc {
namespace {

constexpr std::array<std::string_view, 11> kMethods = {
    "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT", "PRI", "PROPFIND"};

// Case-insensitive comparison of a wire token against a literal. Both sides are folded:
// folding only the input would make every uppercase needle ("GET", "HTTP/1.1", "Host")
// fail to match, which silently disables the whole classifier.
inline bool ci_equal(std::span<const std::uint8_t> a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const int left = std::tolower(static_cast<unsigned char>(a[i]));
        const int right = std::tolower(static_cast<unsigned char>(b[i]));
        if (left != right) return false;
    }
    return true;
}

// Split an authority into host / port. Handles "[::1]:443", "host:80", "1.2.3.4".
void split_authority(std::string_view raw, std::string& host, std::uint16_t& port,
                     bool& is_ip) {
    host.clear();
    port = 0;
    is_ip = false;
    while (!raw.empty() && (raw.front() == ' ' || raw.front() == '\t')) raw.remove_prefix(1);
    while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\t' || raw.back() == '\r')) {
        raw.remove_suffix(1);
    }
    if (raw.empty()) return;

    std::string_view authority = raw;
    std::string_view port_text;

    if (authority.front() == '[') {
        const std::size_t close = authority.find(']');
        if (close == std::string_view::npos) return;
        host.assign(authority.substr(1, close - 1));
        const std::string_view rest = authority.substr(close + 1);
        if (!rest.empty()) {
            if (rest.front() != ':') return;
            port_text = rest.substr(1);
        }
    } else {
        const std::size_t colon = authority.rfind(':');
        // A raw IPv6 literal has several colons; only strip when exactly one is present.
        if (colon != std::string_view::npos && authority.find(':') == colon) {
            host.assign(authority.substr(0, colon));
            port_text = authority.substr(colon + 1);
        } else {
            host.assign(authority);
        }
    }

    if (!port_text.empty()) {
        if (port_text.size() > 5) { host.clear(); return; }
        unsigned value = 0;
        for (char c : port_text) {
            if (c < '0' || c > '9') { host.clear(); return; }
            value = value * 10 + static_cast<unsigned>(c - '0');
        }
        if (value == 0 || value > 65535) { host.clear(); return; }
        port = static_cast<std::uint16_t>(value);
    }

    // Accept either a DNS name or an IP literal; reject anything else.
    if (IpAddress::parse(host).family != IpFamily::none) {
        is_ip = true;
        for (char& c : host) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return;
    }
    if (auto norm = normalize_hostname(host)) {
        host = std::move(*norm);
        return;
    }
    host.clear();
}

}  // namespace

HttpRequest parse_http(std::span<const std::uint8_t> data) noexcept {
    HttpRequest out;
    if (data.size() < 12) return out;

    // 1. method token. The first byte must be a letter and the token must be one of the
    //    methods we recognise, followed by exactly one space.
    const std::uint8_t first = data[0];
    if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z'))) return out;
    std::size_t method_len = 0;
    bool method_ok = false;
    for (std::string_view m : kMethods) {
        if (data.size() < m.size() + 1) continue;
        if (ci_equal(data.first(m.size()), m) && data[m.size()] == ' ') {
            method_len = m.size();
            method_ok = true;
            break;
        }
    }
    if (!method_ok) return out;
    out.method_length = method_len;

    // 2. request target must be non-empty and free of spaces/controls
    std::size_t p = method_len + 1;
    const std::size_t target_start = p;
    while (p < data.size() && data[p] != ' ' && data[p] != '\r' && data[p] != '\n') {
        const std::uint8_t c = data[p];
        if (c < 0x21 || c == 0x7f) return out;
        ++p;
    }
    if (p == target_start || p >= data.size() || data[p] != ' ') return out;

    // 3. version token must be HTTP/1.0 or HTTP/1.1
    ++p;  // consume the space
    const std::size_t version_start = p;
    while (p < data.size() && data[p] != '\r' && data[p] != '\n') {
        if (data[p] == ' ') return out;
        ++p;
    }
    const std::span<const std::uint8_t> version = data.subspan(version_start, p - version_start);
    static constexpr std::string_view kHttp10 = "HTTP/1.0";
    static constexpr std::string_view kHttp11 = "HTTP/1.1";
    if (!ci_equal(version, kHttp10) && !ci_equal(version, kHttp11)) {
        // A known method followed by a space but no HTTP/1.x token is not something we
        // should act on (e.g. an SMTP/IMAP verb, or binary noise).
        return out;
    }

    // 4. end of the request line
    std::size_t line_end = p;
    if (p + 1 < data.size() && data[p] == '\r' && data[p + 1] == '\n') {
        p += 2;
    } else if (p < data.size() && data[p] == '\n') {
        ++p;
    } else {
        out.status = HttpRequest::Status::partial;
        out.missing_bytes = 1;
        return out;
    }
    (void)line_end;
    out.request_line_end = p;

    // 5. header block
    bool header_terminated = false;
    while (true) {
        if (p >= data.size()) {
            out.status = HttpRequest::Status::partial;
            out.missing_bytes = 1;
            return out;
        }
        if (p > kMaxHttpHeaderBytes) {
            out.status = HttpRequest::Status::too_large;
            return out;
        }
        // empty line -> end of headers
        if (data[p] == '\r' && p + 1 < data.size() && data[p + 1] == '\n') {
            p += 2;
            header_terminated = true;
            break;
        }
        if (data[p] == '\n') {
            ++p;
            header_terminated = true;
            break;
        }

        // header field line
        std::size_t name_start = p;
        while (p < data.size() && data[p] != ':' && data[p] != '\r' && data[p] != '\n') {
            ++p;
        }
        const std::size_t name_len = p - name_start;
        if (p >= data.size()) {
            out.status = HttpRequest::Status::partial;
            out.missing_bytes = 1;
            return out;
        }
        if (data[p] != ':') {
            // obs-fold / malformed line
            out.status = HttpRequest::Status::malformed;
            return out;
        }
        const std::span<const std::uint8_t> name = data.subspan(name_start, name_len);
        ++p;  // consume ':'

        std::size_t value_start = p;
        while (p < data.size() && data[p] != '\r' && data[p] != '\n') ++p;
        std::size_t value_end = p;
        while (value_end > value_start &&
               (data[value_end - 1] == ' ' || data[value_end - 1] == '\t')) {
            --value_end;
        }
        while (value_start < value_end &&
               (data[value_start] == ' ' || data[value_start] == '\t')) {
            ++value_start;
        }

        if (out.host_header_offset == 0 && ci_equal(name, "host")) {
            out.host_header_offset = name_start;
            out.host_value_offset = value_start;
            out.host_value_length = value_end - value_start;
            std::string_view raw(reinterpret_cast<const char*>(data.data() + value_start),
                                 value_end - value_start);
            std::string host;
            std::uint16_t port = 0;
            bool is_ip = false;
            split_authority(raw, host, port, is_ip);
            if (!host.empty()) {
                out.host = std::move(host);
                out.host_port = port;
                out.host_is_ip = is_ip;
                out.has_host = true;
            }
        }

        if (p + 1 < data.size() && data[p] == '\r' && data[p + 1] == '\n') {
            p += 2;
        } else if (p < data.size() && data[p] == '\n') {
            ++p;
        } else {
            out.status = HttpRequest::Status::partial;
            out.missing_bytes = 1;
            return out;
        }
    }

    if (!header_terminated) {
        out.status = HttpRequest::Status::partial;
        return out;
    }
    out.headers_end = p;
    out.status = HttpRequest::Status::complete;
    return out;
}

}  // namespace zc
