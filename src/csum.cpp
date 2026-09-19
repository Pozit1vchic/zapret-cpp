#include "csum.hpp"

namespace zc {

std::uint32_t sum_bytes(const std::uint8_t* data, std::size_t len, std::uint32_t seed) {
    std::uint32_t sum = seed;
    std::size_t i = 0;
    for (; i + 1 < len; i += 2) {
        sum += (static_cast<std::uint32_t>(data[i]) << 8) | data[i + 1];
    }
    if (i < len) {
        sum += static_cast<std::uint32_t>(data[i]) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return sum;
}

std::uint16_t fold_sum(std::uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum & 0xffffu);
}

std::uint16_t checksum16(const void* data, std::size_t len, std::uint32_t seed) {
    return fold_sum(sum_bytes(static_cast<const std::uint8_t*>(data), len, seed));
}

}
