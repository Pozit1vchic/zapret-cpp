// HTTP/1.x request-line and header parsing.
//
// The parser is deliberately strict: a payload is only classified as HTTP when the
// request line carries a known method *and* an "HTTP/1.x" version token, and a Host
// value is only accepted when it appears as a real header field name at a line
// boundary. Header values that merely contain the substring "host:" are ignored.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace zc {

inline constexpr std::size_t kMaxHttpHeaderBytes = 16384;  // request line + headers + CRLF

struct HttpRequest {
    enum class Status : std::uint8_t {
        not_http = 0,   // definitely not an HTTP/1.x request
        partial,        // looks like HTTP/1.x but the capture is cut short
        complete,       // request line + full header block present
        too_large,      // header block exceeds kMaxHttpHeaderBytes
        malformed,      // framing contradicts HTTP (bad version token, bad Host, ...)
    };

    Status status = Status::not_http;

    bool has_host = false;   // a syntactically valid Host header was found
    bool host_is_ip = false;
    std::string host;        // lower-cased; no port, no brackets
    std::uint16_t host_port = 0;  // explicit port when present, otherwise 0

    std::size_t method_length = 0;
    std::size_t request_line_end = 0;  // offset of the first header byte
    std::size_t headers_end = 0;       // offset just past the terminating CRLF
    std::size_t host_header_offset = 0;
    std::size_t host_value_offset = 0;
    std::size_t host_value_length = 0;
    std::size_t missing_bytes = 0;

    [[nodiscard]] bool usable() const noexcept {
        return status == Status::complete && has_host;
    }
};

[[nodiscard]] HttpRequest parse_http(std::span<const std::uint8_t> data) noexcept;

}  // namespace zc
