#include "netscope/protocol/packet_parser.h"

#include <arpa/inet.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

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
    case 1U:
        return "ICMP (1)";
    case 6U:
        return "TCP (6)";
    case 17U:
        return "UDP (17)";
    case 58U:
        return "ICMPv6 (58)";
    default:
        return "Unknown (" + std::to_string(value) + ')';
    }
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
    node.fields.push_back(field(
        "header_checksum", hex_value(checksum, 4), hex_value(checksum, 4),
        offset + 10U, 2U));
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

