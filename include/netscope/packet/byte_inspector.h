#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace netscope::packet {

enum class byte_order {
    big_endian,
    little_endian,
};

[[nodiscard]] std::vector<std::uint8_t> parse_hex_pattern(std::string_view text);

[[nodiscard]] std::vector<std::size_t> find_bytes(
    const std::vector<std::uint8_t>& bytes,
    const std::vector<std::uint8_t>& pattern);

[[nodiscard]] std::uint64_t interpret_unsigned(
    const std::vector<std::uint8_t>& bytes,
    std::size_t offset,
    std::size_t width,
    byte_order order);

}  // namespace netscope::packet
