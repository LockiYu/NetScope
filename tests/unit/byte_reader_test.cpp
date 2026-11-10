#include "netscope/packet/byte_reader.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace {

using netscope::packet::byte_reader;
using netscope::packet::byte_view;
using netscope::packet::parse_error;

TEST(byte_reader_test, reads_big_and_little_endian_values) {
    const std::vector<std::uint8_t> bytes{
        0x12, 0x34, 0x78, 0x56, 0x01, 0x23, 0x45, 0x67,
        0xef, 0xcd, 0xab, 0x89,
    };
    byte_reader reader{byte_view{bytes}};

    EXPECT_EQ(reader.read_u16_be(), 0x1234U);
    EXPECT_EQ(reader.read_u16_le(), 0x5678U);
    EXPECT_EQ(reader.read_u32_be(), 0x01234567U);
    EXPECT_EQ(reader.read_u32_le(), 0x89abcdefU);
    EXPECT_EQ(reader.position(), bytes.size());
    EXPECT_EQ(reader.remaining(), 0U);
}

TEST(byte_reader_test, returns_bounded_subviews_and_advances) {
    const std::vector<std::uint8_t> bytes{0x10, 0x20, 0x30, 0x40};
    byte_reader reader{byte_view{bytes}};

    reader.skip(1);
    const auto selected = reader.read_bytes(2);

    ASSERT_EQ(selected.size(), 2U);
    EXPECT_EQ(selected.at(0), 0x20U);
    EXPECT_EQ(selected.at(1), 0x30U);
    EXPECT_EQ(reader.position(), 3U);
}

TEST(byte_reader_test, reports_exact_bounds_on_truncated_input) {
    const std::vector<std::uint8_t> bytes{0xaa, 0xbb, 0xcc};
    byte_reader reader{byte_view{bytes}};

    static_cast<void>(reader.read_u8());

    try {
        static_cast<void>(reader.read_u32_be());
        FAIL() << "Expected parse_error";
    } catch (const parse_error& error) {
        EXPECT_EQ(error.offset(), 1U);
        EXPECT_EQ(error.requested(), 4U);
        EXPECT_EQ(error.available(), 2U);
    }

    EXPECT_EQ(reader.position(), 1U);
}

TEST(byte_reader_test, rejects_out_of_range_single_byte_access) {
    const std::vector<std::uint8_t> bytes{0x01};
    const byte_view view{bytes};

    EXPECT_THROW(static_cast<void>(view.at(1)), parse_error);
}

}  // namespace

