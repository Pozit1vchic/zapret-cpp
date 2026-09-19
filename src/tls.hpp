#pragma once

#include <cstddef>
#include <cstdint>

namespace zc {

struct TlsClientHello {
    bool          valid      = false;
    std::size_t   sni_offset = 0;
    std::size_t   sni_length = 0;
    std::uint16_t list_length = 0;
};

TlsClientHello parse_client_hello(const std::uint8_t* data, std::size_t len);

}
