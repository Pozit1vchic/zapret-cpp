#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace zc {

struct HttpRequest {
    bool        valid = false;
    std::size_t method_end = 0;
    std::string host;
    std::size_t host_header_offset = 0;
    std::size_t host_value_offset = 0;
    std::size_t host_value_length = 0;
};

HttpRequest parse_http_request(const std::uint8_t* data, std::size_t len);

}
