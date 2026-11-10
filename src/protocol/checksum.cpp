#include "netscope/protocol/checksum.h"

#include <cstddef>
#include <cstdint>

namespace netscope::protocol {

std::uint16_t internet_checksum(const packet::byte_view bytes) noexcept {
    std::uint32_t sum{0U};
    std::size_t offset{0U};

    while (offset + 1U < bytes.size()) {
        const auto word = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(bytes.data()[offset]) << 8U) |
            static_cast<std::uint16_t>(bytes.data()[offset + 1U]));
        sum += word;
        offset += 2U;
    }

    if (offset < bytes.size()) {
        sum += static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(bytes.data()[offset]) << 8U);
    }

    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xffffU) + (sum >> 16U);
    }

    return static_cast<std::uint16_t>(~sum & 0xffffU);
}

bool has_valid_internet_checksum(const packet::byte_view bytes) noexcept {
    return internet_checksum(bytes) == 0U;
}

}  // namespace netscope::protocol

