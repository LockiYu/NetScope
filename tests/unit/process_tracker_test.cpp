#include "netscope/analysis/process_tracker.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <vector>

namespace {

using netscope::analysis::process_socket;
using netscope::analysis::process_tracker;

std::vector<std::uint8_t> tcp_frame(
    const std::vector<std::uint8_t>& source,
    const std::vector<std::uint8_t>& destination,
    const std::uint16_t source_port,
    const std::uint16_t destination_port) {
    std::vector<std::uint8_t> bytes{
        0, 1, 2, 3, 4, 5,
        6, 7, 8, 9, 10, 11,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 64, 6, 0x00, 0x00,
    };
    bytes.insert(bytes.end(), source.begin(), source.end());
    bytes.insert(bytes.end(), destination.begin(), destination.end());
    bytes.push_back(static_cast<std::uint8_t>(source_port >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(source_port));
    bytes.push_back(static_cast<std::uint8_t>(destination_port >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(destination_port));
    bytes.insert(bytes.end(), {0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x40, 0, 0, 0, 0, 0});
    return bytes;
}

netscope::capture::captured_packet packet_from(std::vector<std::uint8_t> bytes) {
    const auto length = static_cast<std::uint32_t>(bytes.size());
    return netscope::capture::captured_packet{
        std::chrono::system_clock::time_point{std::chrono::microseconds{1000000}},
        length,
        length,
        std::move(bytes),
    };
}

process_socket tcp_socket(
    const std::string& local,
    const std::uint16_t local_port,
    const std::string& remote,
    const std::uint16_t remote_port) {
    return process_socket{"tcp", local, local_port, remote, remote_port, "curl", 4242};
}

process_tracker tracker_with(std::vector<process_socket> sockets) {
    process_tracker tracker{[] { return std::vector<process_socket>{}; }};
    tracker.ingest(std::move(sockets));
    return tracker;
}

}  // namespace

TEST(process_tracker_test, attributes_outbound_packet_to_process) {
    auto tracker = tracker_with({tcp_socket("192.168.1.10", 1234, "8.8.8.8", 80)});

    const auto owner = tracker.lookup(packet_from(tcp_frame(
        {192, 168, 1, 10},
        {8, 8, 8, 8},
        1234,
        80)));

    ASSERT_TRUE(owner.has_value());
    EXPECT_EQ(owner->name, "curl");
    EXPECT_EQ(owner->pid, 4242);
}

TEST(process_tracker_test, attributes_inbound_packet_to_same_socket) {
    auto tracker = tracker_with({tcp_socket("192.168.1.10", 1234, "8.8.8.8", 80)});

    const auto owner = tracker.lookup(packet_from(tcp_frame(
        {8, 8, 8, 8},
        {192, 168, 1, 10},
        80,
        1234)));

    ASSERT_TRUE(owner.has_value());
    EXPECT_EQ(owner->name, "curl");
}

TEST(process_tracker_test, attributes_listening_socket_by_local_port) {
    auto tracker = tracker_with({tcp_socket("0.0.0.0", 443, "", 0)});

    const auto owner = tracker.lookup(
        "tcp", "10.0.0.5", 50000, "10.0.0.7", 443);

    ASSERT_TRUE(owner.has_value());
    EXPECT_EQ(owner->pid, 4242);
}

TEST(process_tracker_test, prefers_connected_socket_over_listener) {
    process_socket listener = tcp_socket("0.0.0.0", 443, "", 0);
    listener.process_name = "server";
    listener.pid = 1;
    process_socket connected = tcp_socket("192.168.1.10", 50001, "1.1.1.1", 443);
    connected.process_name = "Safari";
    connected.pid = 99;

    auto tracker = tracker_with({listener, connected});
    const auto owner = tracker.lookup(
        "tcp", "192.168.1.10", 50001, "1.1.1.1", 443);

    ASSERT_TRUE(owner.has_value());
    EXPECT_EQ(owner->name, "Safari");
    EXPECT_EQ(owner->pid, 99);
}

TEST(process_tracker_test, returns_nothing_for_unknown_tuple) {
    auto tracker = tracker_with({tcp_socket("192.168.1.10", 1234, "8.8.8.8", 80)});

    EXPECT_FALSE(tracker.lookup("tcp", "192.168.1.10", 1235, "8.8.8.8", 80).has_value());
    EXPECT_FALSE(tracker.lookup("udp", "192.168.1.10", 1234, "8.8.8.8", 80).has_value());
}

TEST(process_tracker_test, ignores_frames_without_transport_ports) {
    std::vector<std::uint8_t> arp{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x06,
        0, 1, 8, 0, 6, 4, 0, 1, 0, 1, 2, 3, 4, 5,
        192, 168, 1, 10, 0, 0, 0, 0, 0, 0,
        192, 168, 1, 1,
    };
    auto tracker = tracker_with({tcp_socket("192.168.1.10", 1234, "8.8.8.8", 80)});

    EXPECT_FALSE(tracker.lookup(packet_from(std::move(arp))).has_value());
}

TEST(process_tracker_test, refresh_uses_injected_provider) {
    int calls{0};
    process_tracker tracker{[&calls] {
        ++calls;
        return std::vector<process_socket>{
            tcp_socket("10.0.0.2", 6000, "10.0.0.3", 22)};
    }};

    tracker.refresh();
    tracker.refresh();

    EXPECT_EQ(calls, 2);
    EXPECT_EQ(tracker.socket_count(), 1U);
    const auto owner = tracker.lookup("tcp", "10.0.0.2", 6000, "10.0.0.3", 22);
    ASSERT_TRUE(owner.has_value());
    EXPECT_EQ(owner->name, "curl");
}

TEST(process_tracker_test, clear_removes_all_attribution) {
    auto tracker = tracker_with({tcp_socket("192.168.1.10", 1234, "8.8.8.8", 80)});

    tracker.clear();

    EXPECT_EQ(tracker.socket_count(), 0U);
    EXPECT_FALSE(tracker.lookup("tcp", "192.168.1.10", 1234, "8.8.8.8", 80).has_value());
}

TEST(process_tracker_test, platform_snapshot_returns_consistent_sockets) {
    const auto sockets = netscope::analysis::list_local_sockets();

    for (const auto& socket : sockets) {
        EXPECT_TRUE(socket.transport == "tcp" || socket.transport == "udp");
        EXPECT_FALSE(socket.local_address.empty());
        EXPECT_GE(socket.pid, 0);
    }
}