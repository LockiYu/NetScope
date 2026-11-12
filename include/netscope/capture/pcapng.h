#pragma once

#include "netscope/capture/pcap_file.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace netscope::capture {

inline constexpr int pcapng_link_type_ethernet = 1;

// Each function returns one complete pcapng block, including the block type,
// the total length fields and any padding, so that a writer can emit the bytes
// without further bookkeeping.
[[nodiscard]] std::vector<std::uint8_t> pcapng_section_header_block();
[[nodiscard]] std::vector<std::uint8_t> pcapng_interface_description_block(
    int link_type,
    int snapshot_length,
    const std::string& name,
    const std::string& description);
[[nodiscard]] std::vector<std::uint8_t> pcapng_enhanced_packet_block(
    const captured_packet& packet,
    const std::optional<std::string>& comment);

}  // namespace netscope::capture
