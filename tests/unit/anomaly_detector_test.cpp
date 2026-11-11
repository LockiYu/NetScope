#include "netscope/analysis/anomaly_detector.h"

#include "netscope/packet/packet_repository.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace {

std::shared_ptr<const netscope::packet::packet_record> syn_packet(
    netscope::packet::packet_repository& repository,
    const std::uint16_t destination_port,
    const std::chrono::system_clock::time_point timestamp) {
    std::vector<std::uint8_t> bytes{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0,
        192, 0, 2, 9, 198, 51, 100, 2,
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

TEST(anomaly_detector_test, reports_port_scan_observations_with_threshold_evidence) {
    netscope::analysis::anomaly_config config;
    config.port_scan_unique_ports = 3U;
    config.port_scan_window = std::chrono::seconds{5};
    netscope::analysis::anomaly_detector detector{config};
    netscope::packet::packet_repository repository{4U};
    const auto base = std::chrono::system_clock::time_point{};

    EXPECT_TRUE(detector.ingest(syn_packet(repository, 20U, base)).empty());
    EXPECT_TRUE(detector.ingest(syn_packet(repository, 21U, base + std::chrono::seconds{1})).empty());
    const auto alerts = detector.ingest(
        syn_packet(repository, 22U, base + std::chrono::seconds{2}));

    ASSERT_EQ(alerts.size(), 1U);
    EXPECT_EQ(alerts.front().rule, "port_scan_observation");
    EXPECT_NE(alerts.front().evidence.find("3 unique destination ports"), std::string::npos);
    EXPECT_NE(alerts.front().evidence.find("192.0.2.9"), std::string::npos);
}

TEST(anomaly_detector_test, reports_malformed_packets_and_redacts_authentication_values) {
    netscope::analysis::anomaly_detector detector;
    auto malformed = std::make_shared<netscope::packet::packet_record>();
    malformed->number = 7U;
    malformed->analysis.name = "Frame";
    malformed->analysis.warnings.push_back("truncated IPv4 header");
    auto alerts = detector.ingest(malformed);
    ASSERT_EQ(alerts.size(), 1U);
    EXPECT_EQ(alerts.front().rule, "malformed_packet");

    auto http = std::make_shared<netscope::packet::packet_record>();
    http->number = 8U;
    http->analysis = netscope::protocol::protocol_node{
        "Frame", {0U, 10U}, {},
        {netscope::protocol::protocol_node{
            "Hypertext Transfer Protocol", {0U, 10U},
            {netscope::protocol::protocol_field{
                "header_authorization", "Basic secret", "Basic secret", {0U, 10U}}},
            {}, {}}},
        {}};
    alerts = detector.ingest(http);
    ASSERT_EQ(alerts.size(), 1U);
    EXPECT_EQ(alerts.front().rule, "cleartext_authentication_field");
    EXPECT_EQ(alerts.front().evidence.find("secret"), std::string::npos);
}

TEST(anomaly_detector_test, reports_high_retransmission_ratios_from_flow_metrics) {
    netscope::analysis::anomaly_detector detector;
    netscope::analysis::tcp_flow_snapshot flow;
    flow.id = 4U;
    flow.packet_count = 20U;
    flow.retransmissions = 6U;

    const auto alerts = detector.evaluate_flows({flow});

    ASSERT_EQ(alerts.size(), 1U);
    EXPECT_EQ(alerts.front().rule, "high_tcp_retransmission_ratio");
}

}  // namespace
