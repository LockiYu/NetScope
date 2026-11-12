#include "netscope/extcap/packet_writer.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace {

using netscope::analysis::process_socket;
using netscope::extcap::packet_writer;
using netscope::extcap::writer_options;

std::vector<std::uint8_t> tcp_frame() {
    return {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, 0, 0x28, 0, 1, 0x40, 0, 64, 6, 0, 0,
        192, 168, 1, 10, 8, 8, 8, 8,
        0x04, 0xd2, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0,
        0x50, 0x02, 0x40, 0, 0, 0, 0, 0,
    };
}

netscope::capture::captured_packet sample_packet() {
    auto bytes = tcp_frame();
    const auto length = static_cast<std::uint32_t>(bytes.size());
    return netscope::capture::captured_packet{
        std::chrono::system_clock::time_point{std::chrono::microseconds{1000000}},
        length,
        length,
        std::move(bytes),
    };
}

bool contains_text(const std::vector<std::uint8_t>& bytes, const std::string& text) {
    return std::search(bytes.begin(), bytes.end(), text.begin(), text.end()) != bytes.end();
}

writer_options options_for(const bool attach_processes) {
    writer_options options;
    options.interface_name = "en0";
    options.description = "Ethernet";
    options.snapshot_length = 262144;
    options.attach_processes = attach_processes;
    options.process_refresh = std::chrono::seconds{5};
    return options;
}

}  // namespace

TEST(packet_writer_test, writes_pcapng_with_process_comment) {
    std::vector<std::uint8_t> output;
    int provider_calls{0};
    packet_writer writer{
        [&output](const std::uint8_t* data, const std::size_t size) {
            output.insert(output.end(), data, data + size);
            return true;
        },
        options_for(true),
        [&provider_calls] {
            ++provider_calls;
            return std::vector<process_socket>{
                {"tcp", "192.168.1.10", 1234, "8.8.8.8", 80, "curl", 42}};
        }};

    ASSERT_TRUE(writer.write_header());
    ASSERT_TRUE(writer.write_packet(sample_packet()));

    EXPECT_EQ(writer.written_packets(), 1U);
    EXPECT_EQ(provider_calls, 1);
    EXPECT_EQ(output[0], 0x0AU);
    EXPECT_TRUE(contains_text(output, "NetScope process: curl (pid 42)"));
    EXPECT_TRUE(contains_text(output, "en0"));
}

TEST(packet_writer_test, skips_attribution_when_disabled) {
    std::vector<std::uint8_t> output;
    int provider_calls{0};
    packet_writer writer{
        [&output](const std::uint8_t* data, const std::size_t size) {
            output.insert(output.end(), data, data + size);
            return true;
        },
        options_for(false),
        [&provider_calls] {
            ++provider_calls;
            return std::vector<process_socket>{};
        }};

    ASSERT_TRUE(writer.write_header());
    ASSERT_TRUE(writer.write_packet(sample_packet()));

    EXPECT_EQ(provider_calls, 0);
    EXPECT_FALSE(contains_text(output, "NetScope process"));
}

TEST(packet_writer_test, reports_sink_failure_without_counting_packet) {
    packet_writer writer{
        [](const std::uint8_t*, const std::size_t) { return false; },
        options_for(false)};

    EXPECT_FALSE(writer.write_header());
    EXPECT_FALSE(writer.write_packet(sample_packet()));
    EXPECT_EQ(writer.written_packets(), 0U);
}

TEST(packet_writer_test, omits_comment_when_no_process_matches) {
    std::vector<std::uint8_t> output;
    packet_writer writer{
        [&output](const std::uint8_t* data, const std::size_t size) {
            output.insert(output.end(), data, data + size);
            return true;
        },
        options_for(true),
        [] { return std::vector<process_socket>{}; }};

    ASSERT_TRUE(writer.write_header());
    ASSERT_TRUE(writer.write_packet(sample_packet()));

    EXPECT_FALSE(contains_text(output, "NetScope process"));
    EXPECT_EQ(writer.written_packets(), 1U);
}
