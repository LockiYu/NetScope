#include "netscope/capture/packet_merger.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using netscope::capture::captured_packet;
using netscope::capture::interface_packet;
using netscope::capture::packet_merger;

captured_packet make_packet(const std::int64_t microseconds, std::uint8_t value) {
    return captured_packet{
        std::chrono::system_clock::time_point{std::chrono::microseconds{microseconds}},
        1U,
        1U,
        {value},
    };
}

TEST(packet_merger_test, orders_packets_from_different_interfaces_by_timestamp) {
    packet_merger merger;
    merger.push(interface_packet{"en1", make_packet(200, 0x02)});
    merger.push(interface_packet{"en0", make_packet(100, 0x01)});

    const auto packets = merger.flush_all();

    ASSERT_EQ(packets.size(), 2U);
    EXPECT_EQ(packets[0].packet.bytes, std::vector<std::uint8_t>{0x01});
    EXPECT_EQ(packets[1].packet.bytes, std::vector<std::uint8_t>{0x02});
}

TEST(packet_merger_test, combines_exact_duplicates_within_the_window) {
    packet_merger merger{std::chrono::microseconds{500}, true};
    merger.push(interface_packet{"en0", make_packet(100, 0xaa)});
    merger.push(interface_packet{"bridge0", make_packet(105, 0xaa)});

    const auto packets = merger.flush_all();

    ASSERT_EQ(packets.size(), 1U);
    EXPECT_EQ(packets.front().interfaces,
              (std::vector<std::string>{"en0", "bridge0"}));
}

TEST(packet_merger_test, keeps_similar_or_distant_packets_separate) {
    packet_merger merger{std::chrono::microseconds{10}, true};
    merger.push(interface_packet{"en0", make_packet(100, 0xaa)});
    merger.push(interface_packet{"en1", make_packet(105, 0xab)});
    merger.push(interface_packet{"en2", make_packet(200, 0xaa)});

    EXPECT_EQ(merger.flush_all().size(), 3U);
}

TEST(packet_merger_test, can_disable_deduplication) {
    packet_merger merger{std::chrono::microseconds{500}, false};
    merger.push(interface_packet{"en0", make_packet(100, 0xaa)});
    merger.push(interface_packet{"en1", make_packet(105, 0xaa)});

    EXPECT_EQ(merger.flush_all().size(), 2U);
}

TEST(packet_merger_test, drains_only_packets_older_than_the_merge_window) {
    packet_merger merger{std::chrono::microseconds{50}, true};
    merger.push(interface_packet{"en0", make_packet(100, 0x01)});
    merger.push(interface_packet{"en1", make_packet(180, 0x02)});

    const auto ready = merger.drain_ready(
        std::chrono::system_clock::time_point{std::chrono::microseconds{200}});

    ASSERT_EQ(ready.size(), 1U);
    EXPECT_EQ(ready.front().packet.bytes, std::vector<std::uint8_t>{0x01});
    EXPECT_EQ(merger.pending_count(), 1U);
}

}  // namespace

