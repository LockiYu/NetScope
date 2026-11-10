#include "netscope/protocol/checksum.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace {

using netscope::packet::byte_view;
using netscope::protocol::has_valid_internet_checksum;
using netscope::protocol::internet_checksum;

TEST(checksum_test, accepts_known_valid_ipv4_header) {
    const std::vector<std::uint8_t> header{
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    };

    EXPECT_EQ(internet_checksum(byte_view{header}), 0U);
    EXPECT_TRUE(has_valid_internet_checksum(byte_view{header}));
}

TEST(checksum_test, rejects_modified_ipv4_header) {
    const std::vector<std::uint8_t> header{
        0x45, 0x00, 0x00, 0x74, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    };

    EXPECT_FALSE(has_valid_internet_checksum(byte_view{header}));
}

TEST(checksum_test, handles_odd_length_input) {
    const std::vector<std::uint8_t> bytes{0x01, 0x02, 0x03};

    EXPECT_EQ(internet_checksum(byte_view{bytes}), 0xfbfdU);
}

}  // namespace

