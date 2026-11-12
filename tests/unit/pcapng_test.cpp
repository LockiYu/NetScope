#include "netscope/capture/pcapng.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

std::uint16_t read_u16(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(bytes[offset]) |
        (static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U));
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset]) |
        (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
        (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
        (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
}

bool contains_text(const std::vector<std::uint8_t>& bytes, const std::string& text) {
    return std::search(bytes.begin(), bytes.end(), text.begin(), text.end()) != bytes.end();
}

netscope::capture::captured_packet packet_with(std::vector<std::uint8_t> bytes) {
    const auto length = static_cast<std::uint32_t>(bytes.size());
    return netscope::capture::captured_packet{
        std::chrono::system_clock::time_point{std::chrono::microseconds{1234567890}},
        length,
        length,
        std::move(bytes),
    };
}

}  // namespace

TEST(pcapng_test, writes_a_section_header_with_byte_order_magic) {
    const auto block = netscope::capture::pcapng_section_header_block();

    ASSERT_GE(block.size(), 28U);
    EXPECT_EQ(block.size() % 4U, 0U);
    EXPECT_EQ(read_u32(block, 0U), 0x0A0D0D0AU);
    EXPECT_EQ(read_u32(block, 4U), block.size());
    EXPECT_EQ(read_u32(block, 8U), 0x1A2B3C4DU);
    EXPECT_EQ(read_u16(block, 12U), 1U);
    EXPECT_EQ(read_u16(block, 14U), 0U);
    EXPECT_EQ(read_u32(block, 16U), 0xFFFFFFFFU);
    EXPECT_EQ(read_u32(block, block.size() - 4U), block.size());
    EXPECT_TRUE(contains_text(block, "NetScope extcap"));
}

TEST(pcapng_test, writes_an_interface_description_with_options) {
    const auto block = netscope::capture::pcapng_interface_description_block(
        1, 262144, "en0", "Ethernet");

    EXPECT_EQ(read_u32(block, 0U), 1U);
    EXPECT_EQ(read_u32(block, 4U), block.size());
    EXPECT_EQ(read_u16(block, 8U), 1U);
    EXPECT_EQ(read_u32(block, 12U), 262144U);
    EXPECT_TRUE(contains_text(block, "en0"));
    EXPECT_TRUE(contains_text(block, "Ethernet"));
    EXPECT_EQ(read_u32(block, block.size() - 4U), block.size());
}

TEST(pcapng_test, writes_an_enhanced_packet_with_comment) {
    const auto packet = packet_with({0x01, 0x02, 0x03, 0x04});
    const auto block = netscope::capture::pcapng_enhanced_packet_block(
        packet, std::string{"NetScope process: curl (pid 42)"});

    EXPECT_EQ(read_u32(block, 0U), 6U);
    EXPECT_EQ(read_u32(block, 4U), block.size());
    EXPECT_EQ(read_u32(block, 8U), 0U);
    const auto timestamp = (static_cast<std::uint64_t>(read_u32(block, 12U)) << 32U) |
        read_u32(block, 16U);
    EXPECT_EQ(timestamp, 1234567890U);
    EXPECT_EQ(read_u32(block, 20U), 4U);
    EXPECT_EQ(read_u32(block, 24U), 4U);
    EXPECT_EQ(block[28], 0x01U);
    EXPECT_EQ(block[31], 0x04U);
    EXPECT_EQ(read_u16(block, 32U), 1U);
    EXPECT_EQ(read_u16(block, 34U), 31U);
    EXPECT_TRUE(contains_text(block, "NetScope process: curl (pid 42)"));
    EXPECT_EQ(read_u32(block, block.size() - 4U), block.size());
}

TEST(pcapng_test, pads_packet_data_and_omits_comment_when_absent) {
    const auto packet = packet_with({0xAA, 0xBB, 0xCC});
    const auto block = netscope::capture::pcapng_enhanced_packet_block(
        packet, std::nullopt);

    EXPECT_EQ(block.size() % 4U, 0U);
    EXPECT_EQ(read_u32(block, 20U), 3U);
    // Data is padded to four bytes, then only the end-of-options marker follows.
    EXPECT_EQ(read_u16(block, 32U), 0U);
    EXPECT_FALSE(contains_text(block, "NetScope process"));
    EXPECT_EQ(block.size(), 40U);
}
