#pragma once

#include <cstddef>
#include <cstdint>

namespace zc {

std::uint32_t sum_bytes(const std::uint8_t* data, std::size_t len, std::uint32_t seed = 0);

std::uint16_t fold_sum(std::uint32_t sum);

std::uint16_t checksum16(const void* data, std::size_t len, std::uint32_t seed = 0);

}
