#include "netscope/analysis/display_filter.h"

#include "netscope/packet/packet_repository.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace {

std::shared_ptr<const netscope::packet::packet_record> tcp_record() {
    std::vector<std::uint8_t> bytes{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, 0, 0x28, 0, 1, 0x40, 0, 64, 6, 0, 0,
        192, 168, 1, 10, 8, 8, 8, 8,
        0x04, 0xd2, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0,
        0x50, 0x02, 0x40, 0, 0, 0, 0, 0,
    };
    netscope::packet::packet_repository repository{1U};
    return repository.append(netscope::capture::merged_packet{
        netscope::capture::captured_packet{
            std::chrono::system_clock::now(),
            static_cast<std::uint32_t>(bytes.size()),
            static_cast<std::uint32_t>(bytes.size()),
            std::move(bytes),
        },
        {"en0"},
    });
}

std::shared_ptr<const netscope::packet::packet_record> dns_record() {
    const std::vector<std::uint8_t> dns{
        0x4d, 0x0f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
        0x00, 0x01, 0x00, 0x01,
    };
    const auto udp_length = static_cast<std::uint16_t>(8U + dns.size());
    const auto total_length = static_cast<std::uint16_t>(20U + udp_length);
    std::vector<std::uint8_t> bytes{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, static_cast<std::uint8_t>(total_length >> 8U),
        static_cast<std::uint8_t>(total_length), 0, 2, 0x40, 0, 64, 17, 0, 0,
        192, 168, 1, 10, 8, 8, 8, 8,
        0x14, 0xe9, 0x14, 0xe9,
        static_cast<std::uint8_t>(udp_length >> 8U),
        static_cast<std::uint8_t>(udp_length),
        0, 0,
    };
    bytes.insert(bytes.end(), dns.begin(), dns.end());
    netscope::packet::packet_repository repository{1U};
    return repository.append(netscope::capture::merged_packet{
        netscope::capture::captured_packet{
            std::chrono::system_clock::now(),
            static_cast<std::uint32_t>(bytes.size()),
            static_cast<std::uint32_t>(bytes.size()),
            std::move(bytes),
        },
        {"en0"},
    });
}

using netscope::analysis::display_filter;
using netscope::analysis::filter_error;

TEST(display_filter_test, matches_protocol_presence_and_common_fields) {
    const auto packet = tcp_record();

    EXPECT_TRUE(display_filter{"tcp"}.matches(*packet));
    EXPECT_TRUE(display_filter{"ip.src == 192.168.1.10"}.matches(*packet));
    EXPECT_TRUE(display_filter{"tcp.dstport == 80"}.matches(*packet));
    EXPECT_FALSE(display_filter{"udp"}.matches(*packet));
    EXPECT_FALSE(display_filter{"ip.dst == 1.1.1.1"}.matches(*packet));
}

TEST(display_filter_test, supports_wireshark_style_field_aliases) {
    const auto dns = dns_record();
    EXPECT_TRUE(display_filter{"dns"}.matches(*dns));
    EXPECT_TRUE(display_filter{"dns.qry.name"}.matches(*dns));
    EXPECT_FALSE(display_filter{"dns.qry.name"}.matches(*tcp_record()));
    EXPECT_TRUE(display_filter{"dns.qry.name == \"example.com\""}.matches(*dns));
    EXPECT_TRUE(display_filter{"dns.id == \"0x4d0f\""}.matches(*dns));
    EXPECT_TRUE(display_filter{"dns.flags.response == 0"}.matches(*dns));
    EXPECT_FALSE(display_filter{"dns.flags.response == 1"}.matches(*dns));
    EXPECT_TRUE(display_filter{"udp.port == 5353"}.matches(*dns));
    EXPECT_TRUE(display_filter{"ip.addr == 192.168.1.10"}.matches(*dns));
    EXPECT_TRUE(display_filter{"ip.addr == 8.8.8.8"}.matches(*dns));
    EXPECT_TRUE(display_filter{"dns.qry.name contains \"example\""}.matches(*dns));
    EXPECT_TRUE(display_filter{"frame contains \"example\""}.matches(*dns));
    EXPECT_TRUE(display_filter{"dns contains \"example\""}.matches(*dns));
    EXPECT_TRUE(display_filter{"udp contains \"example\""}.matches(*dns));
    EXPECT_FALSE(display_filter{"frame contains \"nomatch\""}.matches(*dns));

    const auto tcp = tcp_record();
    EXPECT_TRUE(display_filter{"tcp.port == 80"}.matches(*tcp));
    EXPECT_TRUE(display_filter{"tcp.port == 1234"}.matches(*tcp));
    EXPECT_TRUE(display_filter{"tcp.flags.syn == 1"}.matches(*tcp));
    EXPECT_TRUE(display_filter{"tcp.flags.ack == 0"}.matches(*tcp));
    EXPECT_TRUE(display_filter{"eth.src contains \"06:07\""}.matches(*tcp));
    EXPECT_TRUE(display_filter{"eth.addr contains \"0a:0b\""}.matches(*tcp));
}

TEST(display_filter_test, narrows_to_application_protocols_for_the_demo_filter) {
    const auto dns = dns_record();
    const auto tcp = tcp_record();
    const auto* const expression = "(http or tls or dns) and (ipv4 or ipv6)";

    EXPECT_TRUE(display_filter{expression}.matches(*dns));
    EXPECT_FALSE(display_filter{expression}.matches(*tcp));
    EXPECT_TRUE(display_filter{"(dns or tls) and (ipv4 or ipv6)"}.matches(*dns));
    EXPECT_TRUE(display_filter{"dns or tls or icmp"}.matches(*dns));
}

TEST(display_filter_test, supports_logic_parentheses_strings_and_numbers) {
    const auto packet = tcp_record();

    EXPECT_TRUE(display_filter{
        "tcp and (tcp.srcport >= 1000 or ip.dst == \"8.8.8.8\")"}.matches(*packet));
    EXPECT_TRUE(display_filter{"not udp and frame.len > 40"}.matches(*packet));
    EXPECT_TRUE(display_filter{"tcp.flags contains SYN"}.matches(*packet));
    EXPECT_FALSE(display_filter{"tcp and not tcp"}.matches(*packet));
}

TEST(display_filter_test, reports_the_error_position_for_invalid_expressions) {
    try {
        static_cast<void>(display_filter{"tcp and (udp or"});
        FAIL() << "expected filter_error";
    } catch (const filter_error& error) {
        EXPECT_GT(error.position(), 0U);
        EXPECT_FALSE(std::string{error.what()}.empty());
    }
    EXPECT_THROW(static_cast<void>(display_filter{"tcp === 80"}), filter_error);
}

TEST(display_filter_test, matches_process_attribution_fields) {
    auto bytes = std::vector<std::uint8_t>{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, 0, 0x28, 0, 1, 0x40, 0, 64, 6, 0, 0,
        192, 168, 1, 10, 8, 8, 8, 8,
        0x04, 0xd2, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0,
        0x50, 0x02, 0x40, 0, 0, 0, 0, 0,
    };
    netscope::packet::packet_repository repository{1U};
    const auto attributed = repository.append(
        netscope::capture::merged_packet{
            netscope::capture::captured_packet{
                std::chrono::system_clock::now(),
                static_cast<std::uint32_t>(bytes.size()),
                static_cast<std::uint32_t>(bytes.size()),
                std::move(bytes),
            },
            {"en0"},
        },
        netscope::packet::process_owner{"curl", 4242});

    EXPECT_TRUE(display_filter{"process"}.matches(*attributed));
    EXPECT_TRUE(display_filter{"proc == \"curl\""}.matches(*attributed));
    EXPECT_TRUE(display_filter{"process.pid == 4242"}.matches(*attributed));
    EXPECT_TRUE(display_filter{"process.name == \"curl\" and tcp"}.matches(*attributed));
    EXPECT_FALSE(display_filter{"process == \"Safari\""}.matches(*attributed));
    EXPECT_FALSE(display_filter{"process"}.matches(*tcp_record()));
}

TEST(display_filter_test, empty_expression_matches_every_packet) {
    EXPECT_TRUE(display_filter{""}.matches(*tcp_record()));
}

}  // namespace
