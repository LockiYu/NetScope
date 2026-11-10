#pragma once

#include "netscope/packet/byte_reader.h"

#include <cstdint>

namespace netscope::protocol {

[[nodiscard]] std::uint16_t internet_checksum(packet::byte_view bytes) noexcept;
[[nodiscard]] bool has_valid_internet_checksum(packet::byte_view bytes) noexcept;

}  // namespace netscope::protocol

