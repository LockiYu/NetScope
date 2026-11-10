#include "netscope/packet/byte_inspector.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>

namespace netscope::packet {
namespace {

std::uint8_t hex_digit(const char character) {
    if (character >= '0' && character <= '9') {
        return static_cast<std::uint8_t>(character - '0');
    }
    if (character >= 'a' && character <= 'f') {
        return static_cast<std::uint8_t>(character - 'a' + 10);
    }
    if (character >= 'A' && character <= 'F') {
        return static_cast<std::uint8_t>(character - 'A' + 10);
    }
    throw std::invalid_argument{"hex pattern contains a non-hexadecimal character"};
}

bool supported_width(const std::size_t width) noexcept {
    return width == 1U || width == 2U || width == 4U || width == 8U;
}

}  // namespace

std::vector<std::uint8_t> parse_hex_pattern(const std::string_view text) {
    std::string digits;
    digits.reserve(text.size());
    for (const char character : text) {
        if (std::isxdigit(static_cast<unsigned char>(character)) != 0) {
            digits.push_back(character);
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(character)) != 0 ||
            character == ':' || character == '-') {
            continue;
        }
        throw std::invalid_argument{"hex pattern contains an unsupported separator"};
    }
    if (digits.empty() || digits.size() % 2U != 0U) {
        throw std::invalid_argument{"hex pattern must contain complete bytes"};
    }

    std::vector<std::uint8_t> bytes;
    bytes.reserve(digits.size() / 2U);
    for (std::size_t index = 0U; index < digits.size(); index += 2U) {
        const auto high = static_cast<std::uint8_t>(hex_digit(digits[index]) << 4U);
        bytes.push_back(static_cast<std::uint8_t>(high | hex_digit(digits[index + 1U])));
    }
    return bytes;
}

std::vector<std::size_t> find_bytes(
    const std::vector<std::uint8_t>& bytes,
    const std::vector<std::uint8_t>& pattern) {
    if (pattern.empty()) {
        throw std::invalid_argument{"search pattern cannot be empty"};
    }

    std::vector<std::size_t> matches;
    if (pattern.size() > bytes.size()) {
        return matches;
    }
    for (std::size_t offset = 0U; offset <= bytes.size() - pattern.size(); ++offset) {
        if (std::equal(pattern.begin(), pattern.end(), bytes.begin() +
                static_cast<std::vector<std::uint8_t>::difference_type>(offset))) {
            matches.push_back(offset);
        }
    }
    return matches;
}

std::uint64_t interpret_unsigned(
    const std::vector<std::uint8_t>& bytes,
    const std::size_t offset,
    const std::size_t width,
    const byte_order order) {
    if (!supported_width(width)) {
        throw std::invalid_argument{"integer width must be 1, 2, 4, or 8 bytes"};
    }
    if (offset > bytes.size() || width > bytes.size() - offset) {
        throw std::out_of_range{"integer byte range exceeds packet data"};
    }

    std::uint64_t value{0U};
    if (order == byte_order::big_endian) {
        for (std::size_t index = 0U; index < width; ++index) {
            value = (value << 8U) | bytes[offset + index];
        }
        return value;
    }
    for (std::size_t index = 0U; index < width; ++index) {
        const auto shift = static_cast<unsigned int>(index * 8U);
        value |= static_cast<std::uint64_t>(bytes[offset + index]) << shift;
    }
    return value;
}

}  // namespace netscope::packet
