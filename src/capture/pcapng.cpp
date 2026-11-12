#include "netscope/capture/pcapng.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <string>
#include <utility>

namespace netscope::capture {
namespace {

constexpr std::uint32_t section_header_type = 0x0A0D0D0AU;
constexpr std::uint32_t interface_description_type = 0x00000001U;
constexpr std::uint32_t enhanced_packet_type = 0x00000006U;
constexpr std::uint32_t byte_order_magic = 0x1A2B3C4DU;

constexpr std::uint16_t option_end = 0U;
constexpr std::uint16_t option_comment = 1U;
constexpr std::uint16_t option_interface_name = 2U;
constexpr std::uint16_t option_interface_description = 3U;
constexpr std::uint16_t option_user_application = 4U;

void append_u16(std::vector<std::uint8_t>& output, const std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
}

void append_u32(std::vector<std::uint8_t>& output, const std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xFFU));
}

void append_option(
    std::vector<std::uint8_t>& output,
    const std::uint16_t code,
    const std::string& value) {
    append_u16(output, code);
    append_u16(output, static_cast<std::uint16_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
    while (output.size() % 4U != 0U) {
        output.push_back(0U);
    }
}

std::vector<std::uint8_t> finish_block(
    const std::uint32_t type,
    std::vector<std::uint8_t> body) {
    while (body.size() % 4U != 0U) {
        body.push_back(0U);
    }
    const auto total_length = static_cast<std::uint32_t>(body.size() + 12U);
    std::vector<std::uint8_t> block;
    block.reserve(total_length);
    append_u32(block, type);
    append_u32(block, total_length);
    block.insert(block.end(), body.begin(), body.end());
    append_u32(block, total_length);
    return block;
}

std::uint64_t timestamp_microseconds(const captured_packet& packet) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            packet.timestamp.time_since_epoch())
            .count());
}

}  // namespace

std::vector<std::uint8_t> pcapng_section_header_block() {
    std::vector<std::uint8_t> body;
    append_u32(body, byte_order_magic);
    append_u16(body, 1U);
    append_u16(body, 0U);
    append_u32(body, 0xFFFFFFFFU);
    append_u32(body, 0xFFFFFFFFU);
    append_option(body, option_user_application, "NetScope extcap");
    append_u32(body, option_end);
    return finish_block(section_header_type, std::move(body));
}

std::vector<std::uint8_t> pcapng_interface_description_block(
    const int link_type,
    const int snapshot_length,
    const std::string& name,
    const std::string& description) {
    std::vector<std::uint8_t> body;
    append_u16(body, static_cast<std::uint16_t>(link_type));
    append_u16(body, 0U);
    append_u32(body, static_cast<std::uint32_t>(std::max(snapshot_length, 0)));
    if (!name.empty()) {
        append_option(body, option_interface_name, name);
    }
    if (!description.empty()) {
        append_option(body, option_interface_description, description);
    }
    append_u32(body, option_end);
    return finish_block(interface_description_type, std::move(body));
}

std::vector<std::uint8_t> pcapng_enhanced_packet_block(
    const captured_packet& packet,
    const std::optional<std::string>& comment) {
    const auto timestamp = timestamp_microseconds(packet);
    std::vector<std::uint8_t> body;
    append_u32(body, 0U);
    append_u32(body, static_cast<std::uint32_t>(timestamp >> 32U));
    append_u32(body, static_cast<std::uint32_t>(timestamp & 0xFFFFFFFFU));
    append_u32(body, static_cast<std::uint32_t>(packet.bytes.size()));
    append_u32(body, packet.original_length);
    body.insert(body.end(), packet.bytes.begin(), packet.bytes.end());
    while (body.size() % 4U != 0U) {
        body.push_back(0U);
    }
    if (comment.has_value() && !comment->empty()) {
        append_option(body, option_comment, comment.value());
    }
    append_u32(body, option_end);
    return finish_block(enhanced_packet_type, std::move(body));
}

}  // namespace netscope::capture
