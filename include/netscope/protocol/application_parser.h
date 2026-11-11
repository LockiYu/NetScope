#pragma once

#include "netscope/packet/byte_reader.h"
#include "netscope/protocol/protocol_model.h"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace netscope::protocol {

[[nodiscard]] std::optional<protocol_node> parse_udp_application(
    packet::byte_view frame,
    std::size_t payload_offset,
    std::size_t payload_length,
    std::uint16_t source_port,
    std::uint16_t destination_port);

[[nodiscard]] std::optional<protocol_node> parse_tcp_application(
    packet::byte_view frame,
    std::size_t payload_offset,
    std::size_t payload_length,
    std::uint16_t source_port,
    std::uint16_t destination_port);

}  // namespace netscope::protocol
