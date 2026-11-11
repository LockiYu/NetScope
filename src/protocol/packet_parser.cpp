#include "netscope/protocol/packet_parser.h"

#include "netscope/protocol/application_parser.h"
#include "netscope/protocol/checksum.h"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

namespace netscope::protocol {
namespace {

using packet::byte_reader;
using packet::byte_view;
using packet::parse_error;

std::string hex_value(const std::uint64_t value, const int width) {
    std::ostringstream output;
    output << "0x" << std::hex << std::setfill('0') << std::setw(width) << value;
    return output.str();
}

std::string mac_address(const byte_view bytes) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0U) {
            output << ':';
        }
        output << std::setw(2) << static_cast<unsigned int>(bytes.at(index));
    }
    return output.str();
}

std::string ipv4_address(const byte_view bytes) {
    std::ostringstream output;
    for (std::size_t index = 0; index < 4U; ++index) {
        if (index != 0U) {
            output << '.';
        }
        output << static_cast<unsigned int>(bytes.at(index));
    }
    return output.str();
}

std::string ipv6_address(const byte_view bytes) {
    std::array<char, INET6_ADDRSTRLEN> text{};
    const auto* const result = inet_ntop(
        AF_INET6, static_cast<const void*>(bytes.data()), text.data(), text.size());
    return result == nullptr ? std::string{"invalid IPv6 address"} : std::string{text.data()};
}

std::string ether_type_name(const std::uint16_t value) {
    switch (value) {
    case 0x0800U:
        return "IPv4 (0x0800)";
    case 0x0806U:
        return "ARP (0x0806)";
    case 0x86ddU:
        return "IPv6 (0x86dd)";
    case 0x8100U:
        return "802.1Q VLAN (0x8100)";
    default:
        return "Unknown (" + hex_value(value, 4) + ')';
    }
}

std::string ip_protocol_name(const std::uint8_t value) {
    switch (value) {
    case 0U:
        return "Hop-by-Hop Options (0)";
    case 1U:
        return "ICMP (1)";
    case 6U:
        return "TCP (6)";
    case 17U:
        return "UDP (17)";
    case 43U:
        return "Routing (43)";
    case 44U:
        return "Fragment (44)";
    case 51U:
        return "Authentication Header (51)";
    case 58U:
        return "ICMPv6 (58)";
    case 60U:
        return "Destination Options (60)";
    default:
        return "Unknown (" + std::to_string(value) + ')';
    }
}

std::string ipv6_extension_name(const std::uint8_t type) {
    switch (type) {
    case 0U:
        return "IPv6 Hop-by-Hop Options";
    case 43U:
        return "IPv6 Routing Header";
    case 44U:
        return "IPv6 Fragment Header";
    case 51U:
        return "IP Authentication Header";
    case 60U:
        return "IPv6 Destination Options";
    default:
        return "IPv6 Extension Header";
    }
}

bool is_ipv6_extension_header(const std::uint8_t type) noexcept {
    return type == 0U || type == 43U || type == 44U || type == 51U || type == 60U;
}

protocol_field field(
    std::string name,
    std::string raw_value,
    std::string display_value,
    const std::size_t offset,
    const std::size_t length) {
    return protocol_field{
        std::move(name),
        std::move(raw_value),
        std::move(display_value),
        byte_range{offset, length},
        std::nullopt,
        std::nullopt,
        validation_status::not_checked,
        {},
    };
}

std::uint16_t read_u16_be(const byte_view bytes, const std::size_t offset) {
    byte_reader reader{bytes.subview(offset, 2U)};
    return reader.read_u16_be();
}

std::uint32_t read_u32_be(const byte_view bytes, const std::size_t offset) {
    byte_reader reader{bytes.subview(offset, 4U)};
    return reader.read_u32_be();
}

std::string port_name(const std::uint16_t port) {
    switch (port) {
    case 53U:
        return "53 (DNS)";
    case 67U:
        return "67 (DHCP server)";
    case 68U:
        return "68 (DHCP client)";
    case 80U:
        return "80 (HTTP)";
    case 443U:
        return "443 (HTTPS)";
    case 5353U:
        return "5353 (mDNS)";
    default:
        return std::to_string(port);
    }
}

std::string tcp_flags_text(const std::uint16_t flags) {
    struct flag_name {
        std::uint16_t mask;
        const char* name;
    };
    constexpr std::array<flag_name, 9> names{{
        {0x100U, "NS"}, {0x080U, "CWR"}, {0x040U, "ECE"},
        {0x020U, "URG"}, {0x010U, "ACK"}, {0x008U, "PSH"},
        {0x004U, "RST"}, {0x002U, "SYN"}, {0x001U, "FIN"},
    }};

    std::string result;
    for (const auto& item : names) {
        if ((flags & item.mask) == 0U) {
            continue;
        }
        if (!result.empty()) {
            result += ", ";
        }
        result += item.name;
    }
    return result.empty() ? "none" : result;
}

protocol_node parse_tcp(
    const byte_view frame,
    const std::size_t offset,
    const std::size_t payload_length) {
    const auto available = std::min(frame.size() - offset, payload_length);
    protocol_node node{"Transmission Control Protocol", byte_range{offset, available}, {}, {}, {}};
    if (available < 20U) {
        node.warnings.push_back("truncated TCP header");
        return node;
    }

    const auto source_port = read_u16_be(frame, offset);
    const auto destination_port = read_u16_be(frame, offset + 2U);
    const auto sequence_number = read_u32_be(frame, offset + 4U);
    const auto acknowledgement_number = read_u32_be(frame, offset + 8U);
    const auto data_offset_words = static_cast<std::uint8_t>(frame.at(offset + 12U) >> 4U);
    const auto header_length = static_cast<std::size_t>(data_offset_words) * 4U;
    const auto flags = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(frame.at(offset + 12U) & 0x01U) << 8U) |
        static_cast<std::uint16_t>(frame.at(offset + 13U)));

    node.fields.push_back(field(
        "source_port", std::to_string(source_port), port_name(source_port), offset, 2U));
    node.fields.push_back(field(
        "destination_port", std::to_string(destination_port), port_name(destination_port),
        offset + 2U, 2U));
    node.fields.push_back(field(
        "sequence_number", std::to_string(sequence_number), std::to_string(sequence_number),
        offset + 4U, 4U));
    node.fields.push_back(field(
        "acknowledgement_number", std::to_string(acknowledgement_number),
        std::to_string(acknowledgement_number), offset + 8U, 4U));
    node.fields.push_back(field(
        "header_length", std::to_string(data_offset_words),
        std::to_string(header_length) + " bytes", offset + 12U, 1U));
    node.fields.push_back(field(
        "flags", hex_value(flags, 3), tcp_flags_text(flags), offset + 12U, 2U));
    node.fields.push_back(field(
        "window_size", std::to_string(read_u16_be(frame, offset + 14U)),
        std::to_string(read_u16_be(frame, offset + 14U)), offset + 14U, 2U));
    node.fields.push_back(field(
        "checksum", hex_value(read_u16_be(frame, offset + 16U), 4),
        hex_value(read_u16_be(frame, offset + 16U), 4), offset + 16U, 2U));
    node.fields.push_back(field(
        "urgent_pointer", std::to_string(read_u16_be(frame, offset + 18U)),
        std::to_string(read_u16_be(frame, offset + 18U)), offset + 18U, 2U));

    if (header_length < 20U || header_length > available) {
        node.warnings.push_back("invalid or truncated TCP header length");
        return node;
    }
    if (header_length > 20U) {
        node.fields.push_back(field(
            "options", "", std::to_string(header_length - 20U) + " bytes",
            offset + 20U, header_length - 20U));
    }
    if (available > header_length) {
        node.fields.push_back(field(
            "payload", "", std::to_string(available - header_length) + " bytes",
            offset + header_length, available - header_length));
        if (auto application = parse_tcp_application(
                frame,
                offset + header_length,
                available - header_length,
                source_port,
                destination_port);
            application.has_value()) {
            node.children.push_back(std::move(application.value()));
        }
    }
    return node;
}

protocol_node parse_udp(
    const byte_view frame,
    const std::size_t offset,
    const std::size_t payload_length) {
    const auto available = std::min(frame.size() - offset, payload_length);
    protocol_node node{"User Datagram Protocol", byte_range{offset, available}, {}, {}, {}};
    if (available < 8U) {
        node.warnings.push_back("truncated UDP header");
        return node;
    }

    const auto source_port = read_u16_be(frame, offset);
    const auto destination_port = read_u16_be(frame, offset + 2U);
    const auto length = read_u16_be(frame, offset + 4U);
    const auto checksum = read_u16_be(frame, offset + 6U);
    node.fields.push_back(field(
        "source_port", std::to_string(source_port), port_name(source_port), offset, 2U));
    node.fields.push_back(field(
        "destination_port", std::to_string(destination_port), port_name(destination_port),
        offset + 2U, 2U));
    node.fields.push_back(field(
        "length", std::to_string(length), std::to_string(length) + " bytes",
        offset + 4U, 2U));
    node.fields.push_back(field(
        "checksum", hex_value(checksum, 4), hex_value(checksum, 4), offset + 6U, 2U));
    if (length < 8U) {
        node.warnings.push_back("invalid UDP length");
    } else if (static_cast<std::size_t>(length) > available) {
        node.warnings.push_back("truncated UDP payload");
    } else if (length > 8U) {
        node.fields.push_back(field(
            "payload", "", std::to_string(length - 8U) + " bytes",
            offset + 8U, static_cast<std::size_t>(length - 8U)));
        if (auto application = parse_udp_application(
                frame,
                offset + 8U,
                static_cast<std::size_t>(length - 8U),
                source_port,
                destination_port);
            application.has_value()) {
            node.children.push_back(std::move(application.value()));
        }
    }
    return node;
}

std::string icmp_type_name(const std::uint8_t type, const bool ipv6) {
    if (!ipv6) {
        switch (type) {
        case 0U:
            return "Echo reply (0)";
        case 3U:
            return "Destination unreachable (3)";
        case 8U:
            return "Echo request (8)";
        case 11U:
            return "Time exceeded (11)";
        default:
            return "ICMP type " + std::to_string(type);
        }
    }
    switch (type) {
    case 1U:
        return "Destination unreachable (1)";
    case 128U:
        return "Echo request (128)";
    case 129U:
        return "Echo reply (129)";
    case 135U:
        return "Neighbor solicitation (135)";
    case 136U:
        return "Neighbor advertisement (136)";
    default:
        return "ICMPv6 type " + std::to_string(type);
    }
}

protocol_node parse_icmp(
    const byte_view frame,
    const std::size_t offset,
    const std::size_t payload_length,
    const bool ipv6) {
    const auto available = std::min(frame.size() - offset, payload_length);
    protocol_node node{
        ipv6 ? "Internet Control Message Protocol v6" : "Internet Control Message Protocol",
        byte_range{offset, available}, {}, {}, {}};
    if (available < 4U) {
        node.warnings.push_back(ipv6 ? "truncated ICMPv6 header" : "truncated ICMP header");
        return node;
    }

    const auto type = frame.at(offset);
    const auto code = frame.at(offset + 1U);
    node.fields.push_back(field(
        "type", std::to_string(type), icmp_type_name(type, ipv6), offset, 1U));
    node.fields.push_back(field(
        "code", std::to_string(code), std::to_string(code), offset + 1U, 1U));
    node.fields.push_back(field(
        "checksum", hex_value(read_u16_be(frame, offset + 2U), 4),
        hex_value(read_u16_be(frame, offset + 2U), 4), offset + 2U, 2U));
    if (available >= 8U && ((!ipv6 && (type == 0U || type == 8U)) ||
                           (ipv6 && (type == 128U || type == 129U)))) {
        node.fields.push_back(field(
            "identifier", std::to_string(read_u16_be(frame, offset + 4U)),
            std::to_string(read_u16_be(frame, offset + 4U)), offset + 4U, 2U));
        node.fields.push_back(field(
            "sequence_number", std::to_string(read_u16_be(frame, offset + 6U)),
            std::to_string(read_u16_be(frame, offset + 6U)), offset + 6U, 2U));
    }
    return node;
}

void add_transport_child(
    protocol_node& network_node,
    const byte_view frame,
    const std::uint8_t protocol,
    const std::size_t payload_offset,
    const std::size_t payload_length,
    const bool ipv6) {
    switch (protocol) {
    case 1U:
        if (!ipv6) {
            network_node.children.push_back(
                parse_icmp(frame, payload_offset, payload_length, false));
        }
        break;
    case 6U:
        network_node.children.push_back(parse_tcp(frame, payload_offset, payload_length));
        break;
    case 17U:
        network_node.children.push_back(parse_udp(frame, payload_offset, payload_length));
        break;
    case 58U:
        if (ipv6) {
            network_node.children.push_back(
                parse_icmp(frame, payload_offset, payload_length, true));
        }
        break;
    default:
        break;
    }
}

protocol_node parse_arp(const byte_view frame, const std::size_t offset) {
    protocol_node node{"Address Resolution Protocol", byte_range{offset, 0U}, {}, {}, {}};
    const auto available = frame.size() - offset;
    if (available < 8U) {
        node.bytes.length = available;
        node.warnings.push_back("truncated ARP header");
        return node;
    }

    const auto hardware_type = read_u16_be(frame, offset);
    const auto protocol_type = read_u16_be(frame, offset + 2U);
    const auto hardware_length = frame.at(offset + 4U);
    const auto protocol_length = frame.at(offset + 5U);
    const auto operation = read_u16_be(frame, offset + 6U);
    const auto expected_length = 8U +
        (2U * static_cast<std::size_t>(hardware_length)) +
        (2U * static_cast<std::size_t>(protocol_length));

    node.bytes.length = expected_length <= available ? expected_length : available;
    node.fields.push_back(field(
        "hardware_type", hex_value(hardware_type, 4),
        hardware_type == 1U ? "Ethernet (1)" : std::to_string(hardware_type),
        offset, 2U));
    node.fields.push_back(field(
        "protocol_type", hex_value(protocol_type, 4), ether_type_name(protocol_type),
        offset + 2U, 2U));
    node.fields.push_back(field(
        "hardware_size", std::to_string(hardware_length),
        std::to_string(hardware_length) + " bytes", offset + 4U, 1U));
    node.fields.push_back(field(
        "protocol_size", std::to_string(protocol_length),
        std::to_string(protocol_length) + " bytes", offset + 5U, 1U));
    node.fields.push_back(field(
        "operation", std::to_string(operation),
        operation == 1U ? "request (1)" : operation == 2U ? "reply (2)" : std::to_string(operation),
        offset + 6U, 2U));

    if (expected_length > available) {
        node.warnings.push_back("truncated ARP address fields");
        return node;
    }

    if (hardware_length == 6U && protocol_length == 4U) {
        const auto sender_mac_offset = offset + 8U;
        const auto sender_ip_offset = sender_mac_offset + 6U;
        const auto target_mac_offset = sender_ip_offset + 4U;
        const auto target_ip_offset = target_mac_offset + 6U;
        node.fields.push_back(field(
            "sender_mac", mac_address(frame.subview(sender_mac_offset, 6U)),
            mac_address(frame.subview(sender_mac_offset, 6U)), sender_mac_offset, 6U));
        node.fields.push_back(field(
            "sender_ip", ipv4_address(frame.subview(sender_ip_offset, 4U)),
            ipv4_address(frame.subview(sender_ip_offset, 4U)), sender_ip_offset, 4U));
        node.fields.push_back(field(
            "target_mac", mac_address(frame.subview(target_mac_offset, 6U)),
            mac_address(frame.subview(target_mac_offset, 6U)), target_mac_offset, 6U));
        node.fields.push_back(field(
            "target_ip", ipv4_address(frame.subview(target_ip_offset, 4U)),
            ipv4_address(frame.subview(target_ip_offset, 4U)), target_ip_offset, 4U));
    } else {
        node.warnings.push_back("unsupported ARP address sizes");
    }

    return node;
}

protocol_node parse_ipv4(const byte_view frame, const std::size_t offset) {
    protocol_node node{"Internet Protocol Version 4", byte_range{offset, 0U}, {}, {}, {}};
    const auto available = frame.size() - offset;
    if (available < 20U) {
        node.bytes.length = available;
        node.warnings.push_back("truncated IPv4 header");
        return node;
    }

    const auto version_ihl = frame.at(offset);
    const auto version = static_cast<std::uint8_t>(version_ihl >> 4U);
    const auto ihl = static_cast<std::uint8_t>(version_ihl & 0x0fU);
    const auto header_length = static_cast<std::size_t>(ihl) * 4U;
    if (version != 4U || header_length < 20U || header_length > available) {
        node.bytes.length = std::min(available, header_length);
        node.warnings.push_back("invalid or truncated IPv4 header length");
        return node;
    }

    const auto total_length = read_u16_be(frame, offset + 2U);
    const auto identification = read_u16_be(frame, offset + 4U);
    const auto flags_fragment = read_u16_be(frame, offset + 6U);
    const auto protocol = frame.at(offset + 9U);
    const auto checksum = read_u16_be(frame, offset + 10U);
    node.bytes.length = header_length;

    node.fields.push_back(field("version", std::to_string(version), "IPv4", offset, 1U));
    node.fields.push_back(field(
        "header_length", std::to_string(ihl), std::to_string(header_length) + " bytes",
        offset, 1U));
    node.fields.push_back(field(
        "dscp_ecn", hex_value(frame.at(offset + 1U), 2),
        hex_value(frame.at(offset + 1U), 2), offset + 1U, 1U));
    node.fields.push_back(field(
        "total_length", std::to_string(total_length),
        std::to_string(total_length) + " bytes", offset + 2U, 2U));
    node.fields.push_back(field(
        "identification", hex_value(identification, 4), hex_value(identification, 4),
        offset + 4U, 2U));
    node.fields.push_back(field(
        "flags", hex_value(static_cast<std::uint16_t>(flags_fragment >> 13U), 1),
        hex_value(static_cast<std::uint16_t>(flags_fragment >> 13U), 1), offset + 6U, 2U));
    node.fields.push_back(field(
        "fragment_offset", std::to_string(flags_fragment & 0x1fffU),
        std::to_string(flags_fragment & 0x1fffU), offset + 6U, 2U));
    node.fields.push_back(field(
        "time_to_live", std::to_string(frame.at(offset + 8U)),
        std::to_string(frame.at(offset + 8U)), offset + 8U, 1U));
    node.fields.push_back(field(
        "protocol", std::to_string(protocol), ip_protocol_name(protocol), offset + 9U, 1U));
    auto checksum_field = field(
        "header_checksum", hex_value(checksum, 4), hex_value(checksum, 4),
        offset + 10U, 2U);
    checksum_field.validation = has_valid_internet_checksum(
        frame.subview(offset, header_length))
        ? validation_status::valid
        : validation_status::warning;
    if (checksum_field.validation == validation_status::warning) {
        checksum_field.warnings.push_back(
            "checksum mismatch; capture offload may be responsible");
    }
    node.fields.push_back(std::move(checksum_field));
    node.fields.push_back(field(
        "source_address", ipv4_address(frame.subview(offset + 12U, 4U)),
        ipv4_address(frame.subview(offset + 12U, 4U)), offset + 12U, 4U));
    node.fields.push_back(field(
        "destination_address", ipv4_address(frame.subview(offset + 16U, 4U)),
        ipv4_address(frame.subview(offset + 16U, 4U)), offset + 16U, 4U));
    if (header_length > 20U) {
        node.fields.push_back(field(
            "options", "", std::to_string(header_length - 20U) + " bytes",
            offset + 20U, header_length - 20U));
    }
    if (static_cast<std::size_t>(total_length) > available) {
        node.warnings.push_back("truncated IPv4 payload");
    }
    const auto bounded_total_length = std::min(
        static_cast<std::size_t>(total_length), available);
    if ((flags_fragment & 0x1fffU) == 0U && bounded_total_length >= header_length) {
        add_transport_child(
            node,
            frame,
            protocol,
            offset + header_length,
            bounded_total_length - header_length,
            false);
    }
    return node;
}

protocol_node parse_ipv6(const byte_view frame, const std::size_t offset) {
    protocol_node node{"Internet Protocol Version 6", byte_range{offset, 0U}, {}, {}, {}};
    const auto available = frame.size() - offset;
    if (available < 40U) {
        node.bytes.length = available;
        node.warnings.push_back("truncated IPv6 base header");
        return node;
    }

    const auto first_word = read_u32_be(frame, offset);
    const auto version = static_cast<std::uint8_t>(first_word >> 28U);
    const auto traffic_class = static_cast<std::uint8_t>((first_word >> 20U) & 0xffU);
    const auto flow_label = first_word & 0x000fffffU;
    const auto payload_length = read_u16_be(frame, offset + 4U);
    const auto next_header = frame.at(offset + 6U);
    const auto hop_limit = frame.at(offset + 7U);
    node.bytes.length = 40U;

    if (version != 6U) {
        node.warnings.push_back("invalid IPv6 version");
    }
    node.fields.push_back(field("version", std::to_string(version), "IPv6", offset, 1U));
    node.fields.push_back(field(
        "traffic_class", hex_value(traffic_class, 2), hex_value(traffic_class, 2),
        offset, 2U));
    node.fields.push_back(field(
        "flow_label", hex_value(flow_label, 5), hex_value(flow_label, 5), offset, 4U));
    node.fields.push_back(field(
        "payload_length", std::to_string(payload_length),
        std::to_string(payload_length) + " bytes", offset + 4U, 2U));
    node.fields.push_back(field(
        "next_header", std::to_string(next_header), ip_protocol_name(next_header),
        offset + 6U, 1U));
    node.fields.push_back(field(
        "hop_limit", std::to_string(hop_limit), std::to_string(hop_limit),
        offset + 7U, 1U));
    node.fields.push_back(field(
        "source_address", ipv6_address(frame.subview(offset + 8U, 16U)),
        ipv6_address(frame.subview(offset + 8U, 16U)), offset + 8U, 16U));
    node.fields.push_back(field(
        "destination_address", ipv6_address(frame.subview(offset + 24U, 16U)),
        ipv6_address(frame.subview(offset + 24U, 16U)), offset + 24U, 16U));
    if (static_cast<std::size_t>(payload_length) > available - 40U) {
        node.warnings.push_back("truncated IPv6 payload");
    }
    auto current_header = next_header;
    auto cursor = offset + 40U;
    auto remaining = std::min(
        static_cast<std::size_t>(payload_length), available - 40U);
    std::size_t extension_count{0U};
    constexpr std::size_t max_extension_headers{16U};

    while (is_ipv6_extension_header(current_header) &&
           extension_count < max_extension_headers) {
        if (remaining < 2U) {
            node.warnings.push_back("truncated IPv6 extension header");
            return node;
        }

        const auto following_header = frame.at(cursor);
        std::size_t extension_length{0U};
        if (current_header == 44U) {
            extension_length = 8U;
        } else if (current_header == 51U) {
            extension_length =
                (static_cast<std::size_t>(frame.at(cursor + 1U)) + 2U) * 4U;
        } else {
            extension_length =
                (static_cast<std::size_t>(frame.at(cursor + 1U)) + 1U) * 8U;
        }

        protocol_node extension{
            ipv6_extension_name(current_header),
            byte_range{cursor, std::min(extension_length, remaining)},
            {}, {}, {}};
        extension.fields.push_back(field(
            "next_header", std::to_string(following_header),
            ip_protocol_name(following_header), cursor, 1U));
        extension.fields.push_back(field(
            "header_length", std::to_string(extension_length),
            std::to_string(extension_length) + " bytes", cursor + 1U, 1U));

        if (extension_length > remaining || extension_length < 8U) {
            extension.warnings.push_back("invalid or truncated IPv6 extension header");
            node.children.push_back(std::move(extension));
            return node;
        }

        if (current_header == 44U) {
            const auto fragment_data = read_u16_be(frame, cursor + 2U);
            extension.fields.push_back(field(
                "fragment_offset", std::to_string(fragment_data >> 3U),
                std::to_string(fragment_data >> 3U), cursor + 2U, 2U));
            extension.fields.push_back(field(
                "more_fragments", std::to_string(fragment_data & 0x01U),
                (fragment_data & 0x01U) != 0U ? "set" : "not set", cursor + 2U, 2U));
            extension.fields.push_back(field(
                "identification", hex_value(read_u32_be(frame, cursor + 4U), 8),
                hex_value(read_u32_be(frame, cursor + 4U), 8), cursor + 4U, 4U));
        } else if (extension_length > 2U) {
            extension.fields.push_back(field(
                "data", "", std::to_string(extension_length - 2U) + " bytes",
                cursor + 2U, extension_length - 2U));
        }

        node.children.push_back(std::move(extension));
        current_header = following_header;
        cursor += extension_length;
        remaining -= extension_length;
        ++extension_count;
    }

    if (extension_count == max_extension_headers &&
        is_ipv6_extension_header(current_header)) {
        node.warnings.push_back("too many IPv6 extension headers");
        return node;
    }

    add_transport_child(node, frame, current_header, cursor, remaining, true);
    return node;
}

}  // namespace

protocol_node parse_ethernet_frame(const packet::byte_view frame) {
    protocol_node root{"Frame", byte_range{0U, frame.size()}, {}, {}, {}};
    try {
        if (frame.size() < 14U) {
            root.warnings.push_back("truncated Ethernet II header");
            return root;
        }

        const auto destination = mac_address(frame.subview(0U, 6U));
        const auto source = mac_address(frame.subview(6U, 6U));
        auto ether_type = read_u16_be(frame, 12U);
        std::size_t payload_offset = 14U;
        protocol_node ethernet{"Ethernet II", byte_range{0U, 14U}, {}, {}, {}};
        ethernet.fields.push_back(field("destination", destination, destination, 0U, 6U));
        ethernet.fields.push_back(field("source", source, source, 6U, 6U));
        ethernet.fields.push_back(field(
            "ether_type", hex_value(ether_type, 4), ether_type_name(ether_type), 12U, 2U));

        if (ether_type == 0x8100U) {
            if (frame.size() < 18U) {
                ethernet.warnings.push_back("truncated 802.1Q VLAN header");
                root.children.push_back(std::move(ethernet));
                return root;
            }
            const auto tag = read_u16_be(frame, 14U);
            ether_type = read_u16_be(frame, 16U);
            ethernet.bytes.length = 18U;
            ethernet.fields.push_back(field(
                "vlan_tag", hex_value(tag, 4), "VLAN " + std::to_string(tag & 0x0fffU),
                14U, 2U));
            ethernet.fields.push_back(field(
                "encapsulated_ether_type", hex_value(ether_type, 4),
                ether_type_name(ether_type), 16U, 2U));
            payload_offset = 18U;
        }

        switch (ether_type) {
        case 0x0800U:
            ethernet.children.push_back(parse_ipv4(frame, payload_offset));
            break;
        case 0x0806U:
            ethernet.children.push_back(parse_arp(frame, payload_offset));
            break;
        case 0x86ddU:
            ethernet.children.push_back(parse_ipv6(frame, payload_offset));
            break;
        default:
            ethernet.warnings.push_back("unsupported EtherType " + hex_value(ether_type, 4));
            break;
        }

        root.children.push_back(std::move(ethernet));
    } catch (const parse_error& error) {
        root.warnings.push_back(error.what());
    }
    return root;
}

}  // namespace netscope::protocol

