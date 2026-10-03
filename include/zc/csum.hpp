// Internet checksum (RFC 1071) helpers.
//
// Platform independent: no Windows headers, no allocation, no exceptions.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace zc {

// Accumulate the one's-complement sum of `data` into `seed` and fold the result
// into 16 bits. Safe for any pointer/size, including size 0.
[[nodiscard]] std::uint32_t ones_sum(std::span<const std::uint8_t> data,
                                     std::uint32_t seed = 0) noexcept;

// Fold a possibly wide accumulator into a 16 bit value (no complement).
[[nodiscard]] std::uint16_t fold_sum(std::uint32_t sum) noexcept;

// Full Internet checksum: fold_sum() of the one's-complement sum.
[[nodiscard]] std::uint16_t internet_checksum(std::span<const std::uint8_t> data,
                                              std::uint32_t seed = 0) noexcept;

}  // namespace zc
