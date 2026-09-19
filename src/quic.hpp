#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace zc {

struct QuicInitial {
    bool        valid = false;
    std::size_t header_offset = 0;
    std::size_t dcid_offset = 0;
    std::size_t dcid_length = 0;
    std::size_t scid_offset = 0;
    std::size_t scid_length = 0;
    std::size_t token_offset = 0;
    std::size_t token_length = 0;
    std::uint32_t length = 0;
    std::uint8_t  version_first = 0;
};

QuicInitial parse_quic_initial(const std::uint8_t* data, std::size_t len);

std::vector<std::uint8_t> build_fake_quic_initial(std::size_t target_size,
                                                  const QuicInitial* real);

}
