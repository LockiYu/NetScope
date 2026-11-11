#include "netscope/analysis/ip_reassembly.h"

#include "netscope/packet/packet_repository.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace {

std::shared_ptr<const netscope::packet::packet_record> ipv4_fragment(
    netscope::packet::packet_repository& repository,
    const std::uint16_t offset_units,
    const bool more_fragments,
    const std::string& payload) {
    const auto total_length = static_cast<std::uint16_t>(20U + payload.size());
    const auto flags_offset = static_cast<std::uint16_t>(
        (more_fragments ? 0x2000U : 0U) | offset_units);
    std::vector<std::uint8_t> bytes{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0,
        static_cast<std::uint8_t>(total_length >> 8U),
        static_cast<std::uint8_t>(total_length),
        0x12, 0x34,
        static_cast<std::uint8_t>(flags_offset >> 8U),
        static_cast<std::uint8_t>(flags_offset),
        64, 17, 0, 0,
        10, 0, 0, 1, 10, 0, 0, 2,
    };
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return repository.append(netscope::capture::merged_packet{
        netscope::capture::captured_packet{
            std::chrono::system_clock::time_point{},
            static_cast<std::uint32_t>(bytes.size()),
            static_cast<std::uint32_t>(bytes.size()),
            std::move(bytes),
        },
        {"en0"},
    });
}

std::shared_ptr<const netscope::packet::packet_record> ipv6_fragment(
    netscope::packet::packet_repository& repository,
    const std::uint16_t offset_units,
    const bool more_fragments,
    const std::string& payload) {
    const auto payload_length = static_cast<std::uint16_t>(8U + payload.size());
    const auto fragment_bits = static_cast<std::uint16_t>(
        (offset_units << 3U) | (more_fragments ? 1U : 0U));
    std::vector<std::uint8_t> bytes{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x86, 0xdd,
        0x60, 0, 0, 0,
        static_cast<std::uint8_t>(payload_length >> 8U),
        static_cast<std::uint8_t>(payload_length),
        44, 64,
    };
    const std::array<std::uint8_t, 16> source{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::array<std::uint8_t, 16> destination{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    bytes.insert(bytes.end(), source.begin(), source.end());
    bytes.insert(bytes.end(), destination.begin(), destination.end());
    bytes.insert(bytes.end(), {
        17, 0,
        static_cast<std::uint8_t>(fragment_bits >> 8U),
        static_cast<std::uint8_t>(fragment_bits),
        0x01, 0x02, 0x03, 0x04,
    });
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return repository.append(netscope::capture::merged_packet{
        netscope::capture::captured_packet{
            std::chrono::system_clock::time_point{},
            static_cast<std::uint32_t>(bytes.size()),
            static_cast<std::uint32_t>(bytes.size()),
            std::move(bytes),
        },
        {"en0"},
    });
}

TEST(ip_reassembly_test, reassembles_out_of_order_ipv4_fragments) {
    netscope::packet::packet_repository repository{10U};
    netscope::analysis::ip_reassembler reassembler;

    EXPECT_FALSE(reassembler.ingest(ipv4_fragment(repository, 1U, false, "IJKL")));
    const auto result = reassembler.ingest(
        ipv4_fragment(repository, 0U, true, "ABCDEFGH"));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 4U);
    EXPECT_EQ(result->source, "10.0.0.1");
    EXPECT_EQ(result->destination, "10.0.0.2");
    EXPECT_EQ(result->next_header, 17U);
    EXPECT_EQ(std::string(result->payload.begin(), result->payload.end()), "ABCDEFGHIJKL");
    EXPECT_EQ(result->fragment_count, 2U);
    EXPECT_EQ(reassembler.pending_count(), 0U);
}

TEST(ip_reassembly_test, reports_overlapping_fragment_bytes) {
    netscope::packet::packet_repository repository{10U};
    netscope::analysis::ip_reassembler reassembler;

    EXPECT_FALSE(reassembler.ingest(
        ipv4_fragment(repository, 0U, true, "ABCDEFGHIJKLMNOP")));
    const auto result = reassembler.ingest(
        ipv4_fragment(repository, 1U, false, "IJKLMNOP"));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->overlapping_bytes, 8U);
    EXPECT_EQ(std::string(result->payload.begin(), result->payload.end()), "ABCDEFGHIJKLMNOP");
}

TEST(ip_reassembly_test, reassembles_ipv6_fragment_extension_headers) {
    netscope::packet::packet_repository repository{10U};
    netscope::analysis::ip_reassembler reassembler;

    EXPECT_FALSE(reassembler.ingest(
        ipv6_fragment(repository, 0U, true, "ABCDEFGH")));
    const auto result = reassembler.ingest(
        ipv6_fragment(repository, 1U, false, "IJKL"));

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->version, 6U);
    EXPECT_EQ(result->identification, 0x01020304U);
    EXPECT_EQ(result->next_header, 17U);
    EXPECT_EQ(std::string(result->payload.begin(), result->payload.end()), "ABCDEFGHIJKL");
}

}  // namespace
