#include "netscope/analysis/traffic_statistics.h"

#include "netscope/packet/packet_repository.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

namespace {

std::shared_ptr<const netscope::packet::packet_record> tcp_packet(
    netscope::packet::packet_repository& repository,
    const std::chrono::system_clock::time_point timestamp,
    const std::uint16_t destination_port) {
    std::vector<std::uint8_t> bytes{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0,
        192, 0, 2, 1, 198, 51, 100, 2,
        0x04, 0xd2,
        static_cast<std::uint8_t>(destination_port >> 8U),
        static_cast<std::uint8_t>(destination_port),
        0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x40, 0, 0, 0, 0, 0,
    };
    return repository.append(netscope::capture::merged_packet{
        netscope::capture::captured_packet{
            timestamp,
            static_cast<std::uint32_t>(bytes.size()),
            static_cast<std::uint32_t>(bytes.size()),
            std::move(bytes),
        },
        {"en0"},
    });
}

TEST(traffic_statistics_test, aggregates_protocol_hosts_ports_lengths_and_rates) {
    netscope::packet::packet_repository repository{4U};
    netscope::analysis::traffic_statistics statistics;
    const auto base = std::chrono::system_clock::time_point{};

    statistics.ingest(tcp_packet(repository, base, 80U));
    statistics.ingest(tcp_packet(repository, base + std::chrono::seconds{1}, 443U));
    const auto snapshot = statistics.snapshot();

    EXPECT_EQ(snapshot.total_packets, 2U);
    EXPECT_EQ(snapshot.total_bytes, 108U);
    EXPECT_EQ(snapshot.protocol_counts.at("TCP"), 2U);
    EXPECT_EQ(snapshot.host_counts.at("192.0.2.1"), 2U);
    EXPECT_EQ(snapshot.host_counts.at("198.51.100.2"), 2U);
    EXPECT_EQ(snapshot.port_counts.at(80U), 1U);
    EXPECT_EQ(snapshot.port_counts.at(443U), 1U);
    EXPECT_DOUBLE_EQ(snapshot.packet_rate, 2.0);
    EXPECT_DOUBLE_EQ(snapshot.byte_rate, 108.0);
}

TEST(traffic_statistics_test, clears_all_accumulated_state) {
    netscope::packet::packet_repository repository{1U};
    netscope::analysis::traffic_statistics statistics;
    statistics.ingest(tcp_packet(repository, std::chrono::system_clock::now(), 80U));

    statistics.clear();

    EXPECT_EQ(statistics.snapshot().total_packets, 0U);
}

}  // namespace
