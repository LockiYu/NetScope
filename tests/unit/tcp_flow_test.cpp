#include "netscope/analysis/tcp_flow.h"

#include "netscope/packet/packet_repository.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace {

using namespace std::chrono_literals;
using netscope::analysis::tcp_flow_state;
using netscope::analysis::tcp_flow_tracker;

std::shared_ptr<const netscope::packet::packet_record> packet(
    netscope::packet::packet_repository& repository,
    const std::array<std::uint8_t, 4>& source,
    const std::array<std::uint8_t, 4>& destination,
    const std::uint16_t source_port,
    const std::uint16_t destination_port,
    const std::uint32_t sequence,
    const std::uint32_t acknowledgement,
    const std::uint8_t flags,
    const std::string& payload,
    const std::chrono::system_clock::time_point timestamp) {
    const auto total_length = static_cast<std::uint16_t>(40U + payload.size());
    std::vector<std::uint8_t> bytes{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, static_cast<std::uint8_t>(total_length >> 8U),
        static_cast<std::uint8_t>(total_length), 0, 1, 0x40, 0, 64, 6, 0, 0,
    };
    bytes.insert(bytes.end(), source.begin(), source.end());
    bytes.insert(bytes.end(), destination.begin(), destination.end());
    bytes.push_back(static_cast<std::uint8_t>(source_port >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(source_port));
    bytes.push_back(static_cast<std::uint8_t>(destination_port >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(destination_port));
    for (const int shift : {24, 16, 8, 0}) {
        bytes.push_back(static_cast<std::uint8_t>(sequence >> shift));
    }
    for (const int shift : {24, 16, 8, 0}) {
        bytes.push_back(static_cast<std::uint8_t>(acknowledgement >> shift));
    }
    bytes.insert(bytes.end(), {0x50, flags, 0x40, 0, 0, 0, 0, 0});
    bytes.insert(bytes.end(), payload.begin(), payload.end());
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

TEST(tcp_flow_test, tracks_bidirectional_handshake_state_and_rtt) {
    netscope::packet::packet_repository repository{10U};
    tcp_flow_tracker tracker;
    const auto base = std::chrono::system_clock::time_point{};
    const std::array<std::uint8_t, 4> client{10, 0, 0, 1};
    const std::array<std::uint8_t, 4> server{10, 0, 0, 2};

    const auto first = tracker.ingest(packet(
        repository, client, server, 50000U, 80U, 100U, 0U, 0x02U, "", base));
    const auto second = tracker.ingest(packet(
        repository, server, client, 80U, 50000U, 900U, 101U, 0x12U, "", base + 20ms));
    tracker.ingest(packet(
        repository, client, server, 50000U, 80U, 101U, 901U, 0x10U, "", base + 30ms));

    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(first.value(), second.value());
    const auto flows = tracker.snapshot();
    ASSERT_EQ(flows.size(), 1U);
    EXPECT_EQ(flows.front().state, tcp_flow_state::established);
    ASSERT_TRUE(flows.front().round_trip_time.has_value());
    EXPECT_EQ(flows.front().round_trip_time.value(), 20ms);
    EXPECT_EQ(flows.front().packet_count, 3U);
}

TEST(tcp_flow_test, reassembles_out_of_order_data_and_counts_retransmissions) {
    netscope::packet::packet_repository repository{10U};
    tcp_flow_tracker tracker;
    const auto base = std::chrono::system_clock::time_point{};
    const std::array<std::uint8_t, 4> client{10, 0, 0, 1};
    const std::array<std::uint8_t, 4> server{10, 0, 0, 2};

    tracker.ingest(packet(
        repository, client, server, 50000U, 80U, 101U, 0U, 0x18U, "Hello ", base));
    tracker.ingest(packet(
        repository, client, server, 50000U, 80U, 113U, 0U, 0x18U, "World", base + 1ms));
    tracker.ingest(packet(
        repository, client, server, 50000U, 80U, 107U, 0U, 0x18U, "there ", base + 2ms));
    tracker.ingest(packet(
        repository, client, server, 50000U, 80U, 101U, 0U, 0x18U, "Hello ", base + 3ms));

    const auto flow = tracker.snapshot().front();
    EXPECT_EQ(flow.out_of_order_segments, 1U);
    EXPECT_EQ(flow.retransmissions, 1U);
    EXPECT_EQ(
        std::string(flow.client_to_server_data.begin(), flow.client_to_server_data.end()),
        "Hello there World");
}

TEST(tcp_flow_test, tracks_fin_and_reset_terminal_states) {
    netscope::packet::packet_repository repository{10U};
    tcp_flow_tracker tracker;
    const auto base = std::chrono::system_clock::time_point{};
    const std::array<std::uint8_t, 4> one{10, 0, 0, 1};
    const std::array<std::uint8_t, 4> two{10, 0, 0, 2};

    tracker.ingest(packet(repository, one, two, 1U, 2U, 1U, 0U, 0x01U, "", base));
    tracker.ingest(packet(repository, two, one, 2U, 1U, 1U, 2U, 0x01U, "", base + 1ms));
    EXPECT_EQ(tracker.snapshot().front().state, tcp_flow_state::closed);

    tracker.clear();
    tracker.ingest(packet(repository, one, two, 1U, 2U, 1U, 0U, 0x04U, "", base));
    EXPECT_EQ(tracker.snapshot().front().state, tcp_flow_state::reset);
}

}  // namespace
