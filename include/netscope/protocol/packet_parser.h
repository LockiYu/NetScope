#pragma once

#include "netscope/packet/byte_reader.h"
#include "netscope/protocol/protocol_model.h"

namespace netscope::protocol {

[[nodiscard]] protocol_node parse_ethernet_frame(packet::byte_view frame);

}  // namespace netscope::protocol

