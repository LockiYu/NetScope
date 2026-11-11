#include "netscope/protocol/application_parser.h"
#include "netscope/packet/packet_repository.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace {

const netscope::protocol::protocol_field* field(
    const netscope::protocol::protocol_node& node,
    const std::string& name) {
    for (const auto& item : node.fields) {
        if (item.name == name) {
            return &item;
        }
    }
    return nullptr;
}

TEST(application_parser_test, parses_dns_query_names_and_header_counts) {
    const std::vector<std::uint8_t> dns{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
    };

    const auto parsed = netscope::protocol::parse_udp_application(
        netscope::packet::byte_view{dns}, 0U, dns.size(), 53000U, 53U);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->name, "Domain Name System");
    ASSERT_NE(field(*parsed, "transaction_id"), nullptr);
    ASSERT_NE(field(*parsed, "query_name"), nullptr);
    EXPECT_EQ(field(*parsed, "query_name")->display_value, "www.example.com");
}

TEST(application_parser_test, parses_dhcp_message_type_and_transaction) {
    std::vector<std::uint8_t> dhcp(240U, 0U);
    dhcp[0] = 1U;
    dhcp[1] = 1U;
    dhcp[2] = 6U;
    dhcp[4] = 0x39U;
    dhcp[5] = 0x03U;
    dhcp[6] = 0xf3U;
    dhcp[7] = 0x26U;
    dhcp[236] = 0x63U;
    dhcp[237] = 0x82U;
    dhcp[238] = 0x53U;
    dhcp[239] = 0x63U;
    dhcp.insert(dhcp.end(), {53U, 1U, 1U, 255U});

    const auto parsed = netscope::protocol::parse_udp_application(
        netscope::packet::byte_view{dhcp}, 0U, dhcp.size(), 68U, 67U);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->name, "Dynamic Host Configuration Protocol");
    ASSERT_NE(field(*parsed, "message_type"), nullptr);
    EXPECT_EQ(field(*parsed, "message_type")->display_value, "Discover (1)");
}

TEST(application_parser_test, parses_http_request_line_and_headers) {
    const std::string text =
        "GET /index.html HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
    const std::vector<std::uint8_t> bytes{text.begin(), text.end()};

    const auto parsed = netscope::protocol::parse_tcp_application(
        netscope::packet::byte_view{bytes}, 0U, bytes.size(), 55000U, 80U);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->name, "Hypertext Transfer Protocol");
    ASSERT_NE(field(*parsed, "method"), nullptr);
    EXPECT_EQ(field(*parsed, "method")->display_value, "GET");
    ASSERT_NE(field(*parsed, "host"), nullptr);
    EXPECT_EQ(field(*parsed, "host")->display_value, "example.com");
}

TEST(application_parser_test, parses_tls_client_hello_sni_and_alpn) {
    std::vector<std::uint8_t> hello{
        22, 0x03, 0x03, 0, 0,
        1, 0, 0, 0,
        0x03, 0x03,
    };
    hello.insert(hello.end(), 32U, 0U);
    hello.push_back(0U);
    hello.insert(hello.end(), {0, 2, 0x13, 0x01, 1, 0});
    std::vector<std::uint8_t> extensions{
        0, 0, 0, 16, 0, 14, 0, 0, 11,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0, 16, 0, 5, 0, 3, 2, 'h', '2',
    };
    hello.push_back(static_cast<std::uint8_t>(extensions.size() >> 8U));
    hello.push_back(static_cast<std::uint8_t>(extensions.size()));
    hello.insert(hello.end(), extensions.begin(), extensions.end());
    const auto handshake_length = hello.size() - 9U;
    hello[6] = static_cast<std::uint8_t>(handshake_length >> 16U);
    hello[7] = static_cast<std::uint8_t>(handshake_length >> 8U);
    hello[8] = static_cast<std::uint8_t>(handshake_length);
    const auto record_length = hello.size() - 5U;
    hello[3] = static_cast<std::uint8_t>(record_length >> 8U);
    hello[4] = static_cast<std::uint8_t>(record_length);

    const auto parsed = netscope::protocol::parse_tcp_application(
        netscope::packet::byte_view{hello}, 0U, hello.size(), 55000U, 443U);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->name, "Transport Layer Security");
    ASSERT_NE(field(*parsed, "handshake_type"), nullptr);
    EXPECT_EQ(field(*parsed, "handshake_type")->display_value, "ClientHello (1)");
    ASSERT_NE(field(*parsed, "server_name"), nullptr);
    EXPECT_EQ(field(*parsed, "server_name")->display_value, "example.com");
    ASSERT_NE(field(*parsed, "alpn"), nullptr);
    EXPECT_EQ(field(*parsed, "alpn")->display_value, "h2");
}

TEST(application_parser_test, safely_declines_unknown_or_truncated_payloads) {
    const std::vector<std::uint8_t> bytes{1U, 2U, 3U};
    EXPECT_FALSE(netscope::protocol::parse_tcp_application(
        netscope::packet::byte_view{bytes}, 0U, bytes.size(), 1234U, 4321U).has_value());
    EXPECT_FALSE(netscope::protocol::parse_udp_application(
        netscope::packet::byte_view{bytes}, 0U, bytes.size(), 1234U, 4321U).has_value());
}

TEST(application_parser_test, promotes_application_protocol_into_packet_summary) {
    const std::vector<std::uint8_t> dns{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
    };
    const auto ip_length = static_cast<std::uint16_t>(20U + 8U + dns.size());
    const auto udp_length = static_cast<std::uint16_t>(8U + dns.size());
    std::vector<std::uint8_t> frame{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, static_cast<std::uint8_t>(ip_length >> 8U),
        static_cast<std::uint8_t>(ip_length), 0, 1, 0x40, 0, 64, 17, 0, 0,
        192, 0, 2, 1, 8, 8, 8, 8,
        0xcf, 0x08, 0, 53, static_cast<std::uint8_t>(udp_length >> 8U),
        static_cast<std::uint8_t>(udp_length), 0, 0,
    };
    frame.insert(frame.end(), dns.begin(), dns.end());
    netscope::packet::packet_repository repository{1U};

    const auto record = repository.append(netscope::capture::merged_packet{
        netscope::capture::captured_packet{
            std::chrono::system_clock::now(),
            static_cast<std::uint32_t>(frame.size()),
            static_cast<std::uint32_t>(frame.size()),
            std::move(frame),
        },
        {"en0"},
    });

    EXPECT_EQ(record->protocol, "DNS");
    EXPECT_EQ(record->information, "www.example.com");
}

}  // namespace
