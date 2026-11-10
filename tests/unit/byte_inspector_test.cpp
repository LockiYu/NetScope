#include "netscope/packet/byte_inspector.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

using netscope::packet::byte_order;
using netscope::packet::find_bytes;
using netscope::packet::interpret_unsigned;
using netscope::packet::parse_hex_pattern;

TEST(byte_inspector_test, parses_flexible_hex_patterns_and_rejects_invalid_input) {
    EXPECT_EQ(
        parse_hex_pattern("de ad:BE-EF"),
        (std::vector<std::uint8_t>{0xde, 0xad, 0xbe, 0xef}));
    EXPECT_THROW(parse_hex_pattern("abc"), std::invalid_argument);
    EXPECT_THROW(parse_hex_pattern("zz"), std::invalid_argument);
    EXPECT_THROW(parse_hex_pattern("   "), std::invalid_argument);
}

TEST(byte_inspector_test, finds_all_overlapping_byte_sequences) {
    const std::vector<std::uint8_t> bytes{'a', 'b', 'a', 'b', 'a'};

    EXPECT_EQ(
        find_bytes(bytes, std::vector<std::uint8_t>{'a', 'b', 'a'}),
        (std::vector<std::size_t>{0U, 2U}));
    EXPECT_TRUE(find_bytes(bytes, std::vector<std::uint8_t>{'z'}).empty());
}

TEST(byte_inspector_test, interprets_supported_integer_widths_in_both_byte_orders) {
    const std::vector<std::uint8_t> bytes{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

    EXPECT_EQ(interpret_unsigned(bytes, 0U, 1U, byte_order::big_endian), 0x01U);
    EXPECT_EQ(interpret_unsigned(bytes, 0U, 2U, byte_order::big_endian), 0x0123U);
    EXPECT_EQ(interpret_unsigned(bytes, 0U, 4U, byte_order::big_endian), 0x01234567U);
    EXPECT_EQ(
        interpret_unsigned(bytes, 0U, 8U, byte_order::big_endian),
        0x0123456789abcdefULL);
    EXPECT_EQ(interpret_unsigned(bytes, 0U, 2U, byte_order::little_endian), 0x2301U);
    EXPECT_EQ(interpret_unsigned(bytes, 2U, 4U, byte_order::little_endian), 0xab896745U);
}

TEST(byte_inspector_test, rejects_unsupported_widths_and_out_of_bounds_ranges) {
    const std::vector<std::uint8_t> bytes{1, 2, 3, 4};

    EXPECT_THROW(
        interpret_unsigned(bytes, 0U, 3U, byte_order::big_endian),
        std::invalid_argument);
    EXPECT_THROW(
        interpret_unsigned(bytes, 2U, 4U, byte_order::big_endian),
        std::out_of_range);
}

}  // namespace
