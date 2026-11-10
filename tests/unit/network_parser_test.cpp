#include "netscope/protocol/packet_parser.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using netscope::packet::byte_view;
using netscope::protocol::protocol_field;
using netscope::protocol::protocol_node;

const protocol_node* find_node(const protocol_node& node, const std::string& name) {
    if (node.name == name) {
        return &node;
    }
    for (const auto& child : node.children) {
        if (const auto* result = find_node(child, name); result != nullptr) {
            return result;
        }
    }
    return nullptr;
}

const protocol_field* find_field(const protocol_node& node, const std::string& name) {
    const auto result = std::find_if(
        node.fields.begin(), node.fields.end(), [&name](const auto& field) {
            return field.name == name;
        });
    return result == node.fields.end() ? nullptr : &*result;
}

TEST(network_parser_test, parses_ethernet_and_ipv4_headers) {
    const std::vector<std::uint8_t> frame{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x14, 0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 192, 168, 1, 10, 8, 8, 8, 8,
    };

    const auto parsed = netscope::protocol::parse_ethernet_frame(byte_view{frame});
    const auto* ethernet = find_node(parsed, "Ethernet II");
    const auto* ipv4 = find_node(parsed, "Internet Protocol Version 4");

    ASSERT_NE(ethernet, nullptr);
    ASSERT_NE(ipv4, nullptr);
    EXPECT_EQ(find_field(*ethernet, "destination")->display_value,
              "00:11:22:33:44:55");
    EXPECT_EQ(find_field(*ethernet, "source")->display_value,
              "66:77:88:99:aa:bb");
    EXPECT_EQ(find_field(*ipv4, "source_address")->display_value, "192.168.1.10");
    EXPECT_EQ(find_field(*ipv4, "destination_address")->display_value, "8.8.8.8");
    EXPECT_EQ(find_field(*ipv4, "protocol")->display_value, "TCP (6)");
}

TEST(network_parser_test, parses_arp_request_fields) {
    const std::vector<std::uint8_t> frame{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x0c, 0x29, 0x12, 0x34, 0x56,
        0x08, 0x06,
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0x00, 0x0c, 0x29, 0x12, 0x34, 0x56,
        192, 168, 1, 20,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        192, 168, 1, 1,
    };

    const auto parsed = netscope::protocol::parse_ethernet_frame(byte_view{frame});
    const auto* arp = find_node(parsed, "Address Resolution Protocol");

    ASSERT_NE(arp, nullptr);
    EXPECT_EQ(find_field(*arp, "operation")->display_value, "request (1)");
    EXPECT_EQ(find_field(*arp, "sender_ip")->display_value, "192.168.1.20");
    EXPECT_EQ(find_field(*arp, "target_ip")->display_value, "192.168.1.1");
}

TEST(network_parser_test, parses_ipv6_base_header) {
    const std::vector<std::uint8_t> frame{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x86, 0xdd,
        0x60, 0x00, 0x00, 0x01, 0x00, 0x00, 0x11, 0x40,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    };

    const auto parsed = netscope::protocol::parse_ethernet_frame(byte_view{frame});
    const auto* ipv6 = find_node(parsed, "Internet Protocol Version 6");

    ASSERT_NE(ipv6, nullptr);
    EXPECT_EQ(find_field(*ipv6, "source_address")->display_value, "2001:db8::1");
    EXPECT_EQ(find_field(*ipv6, "destination_address")->display_value, "2001:db8::2");
    EXPECT_EQ(find_field(*ipv6, "next_header")->display_value, "UDP (17)");
}

TEST(network_parser_test, reports_truncated_headers_without_throwing) {
    const std::vector<std::uint8_t> frame{0x00, 0x11, 0x22};

    const auto parsed = netscope::protocol::parse_ethernet_frame(byte_view{frame});

    EXPECT_EQ(parsed.name, "Frame");
    ASSERT_FALSE(parsed.warnings.empty());
    EXPECT_NE(parsed.warnings.front().find("truncated"), std::string::npos);
}

TEST(network_parser_test, parses_tcp_header_and_flags) {
    const std::vector<std::uint8_t> frame{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2,
        0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x40, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    const auto parsed = netscope::protocol::parse_ethernet_frame(byte_view{frame});
    const auto* tcp = find_node(parsed, "Transmission Control Protocol");

    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(find_field(*tcp, "source_port")->display_value, "1234");
    EXPECT_EQ(find_field(*tcp, "destination_port")->display_value, "80 (HTTP)");
    EXPECT_EQ(find_field(*tcp, "sequence_number")->display_value, "1");
    EXPECT_NE(find_field(*tcp, "flags")->display_value.find("SYN"), std::string::npos);
}

TEST(network_parser_test, parses_udp_and_icmp_headers) {
    const std::vector<std::uint8_t> udp_frame{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x1c, 0, 1, 0x40, 0,
        64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
        0x14, 0xe9, 0x00, 0x35, 0x00, 0x08, 0x12, 0x34,
    };
    const std::vector<std::uint8_t> icmp_frame{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x1c, 0, 1, 0x40, 0,
        64, 1, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
        8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01,
    };

    const auto udp_parsed = netscope::protocol::parse_ethernet_frame(byte_view{udp_frame});
    const auto icmp_parsed = netscope::protocol::parse_ethernet_frame(byte_view{icmp_frame});
    const auto* udp = find_node(udp_parsed, "User Datagram Protocol");
    const auto* icmp = find_node(icmp_parsed, "Internet Control Message Protocol");

    ASSERT_NE(udp, nullptr);
    ASSERT_NE(icmp, nullptr);
    EXPECT_EQ(find_field(*udp, "source_port")->display_value, "5353 (mDNS)");
    EXPECT_EQ(find_field(*udp, "destination_port")->display_value, "53 (DNS)");
    EXPECT_EQ(find_field(*icmp, "type")->display_value, "Echo request (8)");
}

TEST(network_parser_test, parses_icmpv6_header) {
    const std::vector<std::uint8_t> frame{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x86, 0xdd,
        0x60, 0, 0, 0, 0, 8, 58, 64,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        128, 0, 0, 0, 0x12, 0x34, 0, 1,
    };

    const auto parsed = netscope::protocol::parse_ethernet_frame(byte_view{frame});
    const auto* icmpv6 = find_node(parsed, "Internet Control Message Protocol v6");

    ASSERT_NE(icmpv6, nullptr);
    EXPECT_EQ(find_field(*icmpv6, "type")->display_value, "Echo request (128)");
}

TEST(network_parser_test, walks_ipv6_extension_headers_to_udp) {
    const std::vector<std::uint8_t> frame{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x86, 0xdd,
        0x60, 0, 0, 0, 0, 16, 0, 64,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        17, 0, 1, 0, 0, 0, 0, 0,
        0x14, 0xe9, 0x00, 0x35, 0x00, 0x08, 0, 0,
    };

    const auto parsed = netscope::protocol::parse_ethernet_frame(byte_view{frame});
    const auto* extension = find_node(parsed, "IPv6 Hop-by-Hop Options");
    const auto* udp = find_node(parsed, "User Datagram Protocol");

    ASSERT_NE(extension, nullptr);
    ASSERT_NE(udp, nullptr);
    EXPECT_EQ(find_field(*extension, "next_header")->display_value, "UDP (17)");
    EXPECT_EQ(find_field(*udp, "destination_port")->display_value, "53 (DNS)");
}

}  // namespace

