#include "http.hpp"

#include <cctype>

namespace zc {

namespace {

bool starts_with_ci(const std::uint8_t* p, std::size_t n, const char* needle,
                    std::size_t nlen) {
    if (n < nlen) {
        return false;
    }
    for (std::size_t i = 0; i < nlen; ++i) {
        char a = static_cast<char>(std::tolower(p[i]));
        char b = static_cast<char>(std::tolower(static_cast<unsigned char>(needle[i])));
        if (a != b) {
            return false;
        }
    }
    return true;
}

}

HttpRequest parse_http_request(const std::uint8_t* p, std::size_t n) {
    HttpRequest out;
    if (n < 5) {
        return out;
    }

    const char* methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "};
    bool is_method = false;
    for (const char* m : methods) {
        std::size_t ml = 0;
        while (m[ml] != '\0') {
            ++ml;
        }
        if (starts_with_ci(p, n, m, ml)) {
            is_method = true;
            out.method_end = ml;
            break;
        }
    }
    if (!is_method) {
        return out;
    }

    for (std::size_t i = out.method_end; i + 4 <= n; ++i) {
        if (i + 2 <= n && p[i] == '\r' && p[i + 1] == '\n') {
            if (p[i + 2] == '\r' && p[i + 3] == '\n') {
                break;
            }
            ++i;
            continue;
        }
        if (starts_with_ci(p + i, n - i, "host:", 5)) {
            std::size_t h = i;
            std::size_t v = h + 5;
            while (v < n && (p[v] == ' ' || p[v] == '\t')) {
                ++v;
            }
            std::size_t e = v;
            while (e < n && p[e] != '\r' && p[e] != '\n') {
                ++e;
            }
            if (e > v) {
                out.valid = true;
                out.host_header_offset = h;
                out.host_value_offset = v;
                out.host_value_length = e - v;
                out.host.assign(reinterpret_cast<const char*>(p + v), e - v);

                std::size_t colon = out.host.find(':');
                if (colon != std::string::npos) {
                    out.host.resize(colon);
                }
                return out;
            }
        }
    }

    return out;
}

}
