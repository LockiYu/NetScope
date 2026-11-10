#include "netscope/packet/packet_repository.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

using netscope::capture::captured_packet;
using netscope::capture::merged_packet;
using netscope::packet::packet_repository;

merged_packet make_tcp_packet(std::uint8_t source_last_octet) {
    std::vector<std::uint8_t> bytes{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0, 1, 0x40, 0,
        64, 6, 0, 0, 192, 168, 1, source_last_octet, 8, 8, 8, 8,
        0x04, 0xd2, 0x00, 0x50, 0, 0, 0, 1,
        0, 0, 0, 0, 0x50, 0x02, 0x40, 0,
        0, 0, 0, 0,
    };
    return merged_packet{
        captured_packet{
            std::chrono::system_clock::time_point{},
            static_cast<std::uint32_t>(bytes.size()),
            static_cast<std::uint32_t>(bytes.size()),
            std::move(bytes),
        },
        {"en0"},
    };
}

TEST(packet_repository_test, parses_and_summarizes_appended_packets) {
    packet_repository repository{10};

    const auto record = repository.append(make_tcp_packet(10));

    EXPECT_EQ(record->number, 1U);
    EXPECT_EQ(record->source, "192.168.1.10");
    EXPECT_EQ(record->destination, "8.8.8.8");
    EXPECT_EQ(record->protocol, "TCP");
    EXPECT_NE(record->information.find("1234"), std::string::npos);
    EXPECT_NE(record->information.find("80"), std::string::npos);
}

TEST(packet_repository_test, evicts_oldest_records_at_capacity) {
    packet_repository repository{2};
    static_cast<void>(repository.append(make_tcp_packet(1)));
    static_cast<void>(repository.append(make_tcp_packet(2)));
    static_cast<void>(repository.append(make_tcp_packet(3)));

    ASSERT_EQ(repository.size(), 2U);
    EXPECT_EQ(repository.evicted_count(), 1U);
    EXPECT_EQ(repository.at(0)->number, 2U);
    EXPECT_EQ(repository.at(1)->number, 3U);
}

TEST(packet_repository_test, rejects_zero_capacity_and_out_of_range_access) {
    EXPECT_THROW(packet_repository{0}, std::invalid_argument);

    packet_repository repository{1};
    EXPECT_THROW(static_cast<void>(repository.at(0)), std::out_of_range);
}

}  // namespace

