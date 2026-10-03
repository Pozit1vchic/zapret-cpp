#include "zc/csum.hpp"

namespace zc {

std::uint32_t ones_sum(std::span<const std::uint8_t> data, std::uint32_t seed) noexcept {
    std::uint32_t sum = seed;
    std::size_t i = 0;
    const std::size_t n = data.size();
    for (; i + 1 < n; i += 2) {
        sum += (static_cast<std::uint32_t>(data[i]) << 8) | static_cast<std::uint32_t>(data[i + 1]);
    }
    if (i < n) {
        sum += static_cast<std::uint32_t>(data[i]) << 8;
    }
    // Fold once; folding is associative and idempotent for 16-bit one's complement.
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return sum;
}

std::uint16_t fold_sum(std::uint32_t sum) noexcept {
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum & 0xffffu);
}

std::uint16_t internet_checksum(std::span<const std::uint8_t> data, std::uint32_t seed) noexcept {
    return fold_sum(ones_sum(data, seed));
}

}  // namespace zc
