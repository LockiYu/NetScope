#include "netscope/protocol/application_parser.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

namespace netscope::protocol {
namespace {

protocol_field field(
    std::string name,
    std::string raw,
    std::string display,
    const std::size_t offset,
    const std::size_t length) {
    return protocol_field{
        std::move(name), std::move(raw), std::move(display), byte_range{offset, length},
        std::nullopt, std::nullopt, validation_status::not_checked, {}};
}

std::uint16_t u16(const packet::byte_view bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes.at(offset)) << 8U) |
        static_cast<std::uint16_t>(bytes.at(offset + 1U)));
}

std::uint32_t u24(const packet::byte_view bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes.at(offset)) << 16U) |
           (static_cast<std::uint32_t>(bytes.at(offset + 1U)) << 8U) |
           static_cast<std::uint32_t>(bytes.at(offset + 2U));
}

std::uint32_t u32(const packet::byte_view bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes.at(offset)) << 24U) |
           (static_cast<std::uint32_t>(bytes.at(offset + 1U)) << 16U) |
           (static_cast<std::uint32_t>(bytes.at(offset + 2U)) << 8U) |
           static_cast<std::uint32_t>(bytes.at(offset + 3U));
}

std::string hex(const std::uint32_t value, const int width) {
    std::ostringstream output;
    output << "0x" << std::hex << std::setfill('0') << std::setw(width) << value;
    return output.str();
}

std::string ascii(
    const packet::byte_view frame,
    const std::size_t offset,
    const std::size_t length) {
    std::string result;
    result.reserve(length);
    for (std::size_t index = 0U; index < length; ++index) {
        result.push_back(static_cast<char>(frame.at(offset + index)));
    }
    return result;
}

struct dns_name {
    std::string value;
    std::size_t consumed{0U};
    bool valid{false};
};

dns_name decode_dns_name(
    const packet::byte_view frame,
    const std::size_t payload_offset,
    const std::size_t payload_length,
    const std::size_t start,
    const std::size_t depth = 0U) {
    if (depth > 16U || start < payload_offset ||
        start >= payload_offset + payload_length) {
        return {};
    }
    std::string name;
    std::size_t cursor = start;
    std::size_t consumed{0U};
    while (cursor < payload_offset + payload_length) {
        const auto size = frame.at(cursor);
        if (size == 0U) {
            ++consumed;
            return dns_name{name, consumed, true};
        }
        if ((size & 0xc0U) == 0xc0U) {
            if (cursor + 1U >= payload_offset + payload_length) {
                return {};
            }
            const auto pointer = static_cast<std::size_t>(
                (static_cast<std::uint16_t>(size & 0x3fU) << 8U) |
                frame.at(cursor + 1U));
            const auto suffix = decode_dns_name(
                frame, payload_offset, payload_length, payload_offset + pointer, depth + 1U);
            if (!suffix.valid) {
                return {};
            }
            if (!name.empty() && !suffix.value.empty()) {
                name.push_back('.');
            }
            name += suffix.value;
            consumed += 2U;
            return dns_name{name, consumed, true};
        }
        if (size > 63U || cursor + 1U + size > payload_offset + payload_length) {
            return {};
        }
        if (!name.empty()) {
            name.push_back('.');
        }
        name += ascii(frame, cursor + 1U, size);
        cursor += 1U + size;
        consumed += 1U + size;
    }
    return {};
}

protocol_node parse_dns(
    const packet::byte_view frame,
    const std::size_t offset,
    const std::size_t length) {
    protocol_node node{"Domain Name System", byte_range{offset, length}, {}, {}, {}};
    if (length < 12U) {
        node.warnings.push_back("truncated DNS header");
        return node;
    }
    const auto identifier = u16(frame, offset);
    const auto flags = u16(frame, offset + 2U);
    const auto questions = u16(frame, offset + 4U);
    const auto answers = u16(frame, offset + 6U);
    node.fields.push_back(field(
        "transaction_id", hex(identifier, 4), hex(identifier, 4), offset, 2U));
    node.fields.push_back(field(
        "flags", hex(flags, 4), (flags & 0x8000U) != 0U ? "Response" : "Query",
        offset + 2U, 2U));
    node.fields.push_back(field(
        "question_count", std::to_string(questions), std::to_string(questions),
        offset + 4U, 2U));
    node.fields.push_back(field(
        "answer_count", std::to_string(answers), std::to_string(answers),
        offset + 6U, 2U));

    std::size_t cursor = offset + 12U;
    for (std::uint16_t index = 0U; index < questions; ++index) {
        const auto name = decode_dns_name(frame, offset, length, cursor);
        if (!name.valid || cursor + name.consumed + 4U > offset + length) {
            node.warnings.push_back("truncated or invalid DNS question");
            return node;
        }
        node.fields.push_back(field(
            "query_name", name.value, name.value, cursor, name.consumed));
        const auto type = u16(frame, cursor + name.consumed);
        node.fields.push_back(field(
            "query_type", std::to_string(type), std::to_string(type),
            cursor + name.consumed, 2U));
        cursor += name.consumed + 4U;
    }

    for (std::uint16_t index = 0U; index < answers && cursor < offset + length; ++index) {
        const auto name = decode_dns_name(frame, offset, length, cursor);
        if (!name.valid || cursor + name.consumed + 10U > offset + length) {
            node.warnings.push_back("truncated or invalid DNS answer");
            return node;
        }
        const auto type_offset = cursor + name.consumed;
        const auto type = u16(frame, type_offset);
        const auto ttl = u32(frame, type_offset + 4U);
        const auto data_length = u16(frame, type_offset + 8U);
        const auto data_offset = type_offset + 10U;
        if (data_offset + data_length > offset + length) {
            node.warnings.push_back("truncated DNS resource record");
            return node;
        }
        protocol_node answer{"DNS Answer", byte_range{cursor, data_offset + data_length - cursor},
                             {}, {}, {}};
        answer.fields.push_back(field("name", name.value, name.value, cursor, name.consumed));
        answer.fields.push_back(field(
            "type", std::to_string(type), std::to_string(type), type_offset, 2U));
        answer.fields.push_back(field(
            "ttl", std::to_string(ttl), std::to_string(ttl) + " seconds",
            type_offset + 4U, 4U));
        if (type == 1U && data_length == 4U) {
            const auto address = std::to_string(frame.at(data_offset)) + "." +
                std::to_string(frame.at(data_offset + 1U)) + "." +
                std::to_string(frame.at(data_offset + 2U)) + "." +
                std::to_string(frame.at(data_offset + 3U));
            answer.fields.push_back(field(
                "address", address, address, data_offset, data_length));
        } else {
            answer.fields.push_back(field(
                "rdata", "", std::to_string(data_length) + " bytes",
                data_offset, data_length));
        }
        node.children.push_back(std::move(answer));
        cursor = data_offset + data_length;
    }
    return node;
}

std::string dhcp_message_type(const std::uint8_t type) {
    switch (type) {
    case 1U: return "Discover (1)";
    case 2U: return "Offer (2)";
    case 3U: return "Request (3)";
    case 4U: return "Decline (4)";
    case 5U: return "ACK (5)";
    case 6U: return "NAK (6)";
    case 7U: return "Release (7)";
    case 8U: return "Inform (8)";
    default: return std::to_string(type);
    }
}

protocol_node parse_dhcp(
    const packet::byte_view frame,
    const std::size_t offset,
    const std::size_t length) {
    protocol_node node{
        "Dynamic Host Configuration Protocol", byte_range{offset, length}, {}, {}, {}};
    if (length < 240U) {
        node.warnings.push_back("truncated DHCP/BOOTP message");
        return node;
    }
    node.fields.push_back(field(
        "operation", std::to_string(frame.at(offset)),
        frame.at(offset) == 1U ? "Boot Request (1)" : "Boot Reply (2)", offset, 1U));
    node.fields.push_back(field(
        "transaction_id", hex(u32(frame, offset + 4U), 8),
        hex(u32(frame, offset + 4U), 8), offset + 4U, 4U));
    const auto cookie = u32(frame, offset + 236U);
    node.fields.push_back(field(
        "magic_cookie", hex(cookie, 8), hex(cookie, 8), offset + 236U, 4U));
    if (cookie != 0x63825363U) {
        node.warnings.push_back("invalid DHCP magic cookie");
        return node;
    }
    std::size_t cursor = offset + 240U;
    while (cursor < offset + length) {
        const auto code = frame.at(cursor++);
        if (code == 255U) {
            break;
        }
        if (code == 0U) {
            continue;
        }
        if (cursor >= offset + length) {
            node.warnings.push_back("truncated DHCP option length");
            break;
        }
        const auto option_length = static_cast<std::size_t>(frame.at(cursor++));
        if (cursor + option_length > offset + length) {
            node.warnings.push_back("truncated DHCP option value");
            break;
        }
        if (code == 53U && option_length == 1U) {
            const auto value = frame.at(cursor);
            node.fields.push_back(field(
                "message_type", std::to_string(value), dhcp_message_type(value),
                cursor, 1U));
        } else if (code == 12U) {
            const auto value = ascii(frame, cursor, option_length);
            node.fields.push_back(field("host_name", value, value, cursor, option_length));
        } else {
            node.fields.push_back(field(
                "option_" + std::to_string(code), "",
                std::to_string(option_length) + " bytes", cursor, option_length));
        }
        cursor += option_length;
    }
    return node;
}

std::string trim(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
        value.erase(value.begin());
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.pop_back();
    }
    return value;
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool looks_like_http(const std::string& text) {
    static const std::vector<std::string> starts{
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/"};
    return std::any_of(starts.begin(), starts.end(), [&](const auto& prefix) {
        return text.rfind(prefix, 0U) == 0U;
    });
}

protocol_node parse_http(
    const packet::byte_view frame,
    const std::size_t offset,
    const std::size_t length) {
    protocol_node node{"Hypertext Transfer Protocol", byte_range{offset, length}, {}, {}, {}};
    const auto text = ascii(frame, offset, length);
    const auto line_end = text.find("\r\n");
    const auto first_line = text.substr(0U, line_end == std::string::npos ? text.size() : line_end);
    node.fields.push_back(field("start_line", first_line, first_line, offset, first_line.size()));
    if (first_line.rfind("HTTP/", 0U) == 0U) {
        const auto first_space = first_line.find(' ');
        const auto second_space = first_space == std::string::npos
            ? std::string::npos : first_line.find(' ', first_space + 1U);
        if (first_space != std::string::npos) {
            const auto status = first_line.substr(
                first_space + 1U,
                second_space == std::string::npos ? std::string::npos : second_space - first_space - 1U);
            node.fields.push_back(field(
                "status_code", status, status, offset + first_space + 1U, status.size()));
        }
    } else {
        const auto first_space = first_line.find(' ');
        const auto second_space = first_space == std::string::npos
            ? std::string::npos : first_line.find(' ', first_space + 1U);
        if (first_space != std::string::npos && second_space != std::string::npos) {
            const auto method = first_line.substr(0U, first_space);
            const auto uri = first_line.substr(first_space + 1U, second_space - first_space - 1U);
            node.fields.push_back(field("method", method, method, offset, method.size()));
            node.fields.push_back(field(
                "request_uri", uri, uri, offset + first_space + 1U, uri.size()));
        }
    }

    std::size_t cursor = line_end == std::string::npos ? text.size() : line_end + 2U;
    while (cursor < text.size()) {
        const auto end = text.find("\r\n", cursor);
        if (end == std::string::npos || end == cursor) {
            break;
        }
        const auto separator = text.find(':', cursor);
        if (separator != std::string::npos && separator < end) {
            const auto name = lower(text.substr(cursor, separator - cursor));
            const auto value = trim(text.substr(separator + 1U, end - separator - 1U));
            std::string field_name = "header_" + name;
            if (name == "host") field_name = "host";
            if (name == "content-length") field_name = "content_length";
            if (name == "transfer-encoding") field_name = "transfer_encoding";
            const auto value_position = text.find(value, separator + 1U);
            node.fields.push_back(field(
                field_name, value, value, offset + value_position, value.size()));
        }
        cursor = end + 2U;
    }
    if (text.find("\r\n\r\n") == std::string::npos) {
        node.warnings.push_back("incomplete HTTP header block");
    }
    return node;
}

std::string tls_version(const std::uint16_t version) {
    switch (version) {
    case 0x0301U: return "TLS 1.0";
    case 0x0302U: return "TLS 1.1";
    case 0x0303U: return "TLS 1.2 / TLS 1.3 legacy";
    case 0x0304U: return "TLS 1.3";
    default: return hex(version, 4);
    }
}

protocol_node parse_tls(
    const packet::byte_view frame,
    const std::size_t offset,
    const std::size_t length) {
    protocol_node node{"Transport Layer Security", byte_range{offset, length}, {}, {}, {}};
    if (length < 5U) {
        node.warnings.push_back("truncated TLS record header");
        return node;
    }
    const auto content_type = frame.at(offset);
    const auto version = u16(frame, offset + 1U);
    const auto record_length = u16(frame, offset + 3U);
    node.fields.push_back(field(
        "content_type", std::to_string(content_type),
        content_type == 22U ? "Handshake (22)" : std::to_string(content_type), offset, 1U));
    node.fields.push_back(field(
        "record_version", hex(version, 4), tls_version(version), offset + 1U, 2U));
    node.fields.push_back(field(
        "record_length", std::to_string(record_length),
        std::to_string(record_length) + " bytes", offset + 3U, 2U));
    if (record_length > length - 5U) {
        node.warnings.push_back("truncated TLS record");
    }
    if (content_type != 22U || length < 9U) {
        return node;
    }
    const auto handshake_type = frame.at(offset + 5U);
    const auto handshake_length = u24(frame, offset + 6U);
    const auto handshake_name = handshake_type == 1U ? "ClientHello (1)"
        : handshake_type == 2U ? "ServerHello (2)" : std::to_string(handshake_type);
    node.fields.push_back(field(
        "handshake_type", std::to_string(handshake_type), handshake_name, offset + 5U, 1U));
    node.fields.push_back(field(
        "handshake_length", std::to_string(handshake_length),
        std::to_string(handshake_length) + " bytes", offset + 6U, 3U));
    if ((handshake_type != 1U && handshake_type != 2U) || length < 44U) {
        return node;
    }

    std::size_t cursor = offset + 9U;
    const auto hello_version = u16(frame, cursor);
    node.fields.push_back(field(
        "hello_version", hex(hello_version, 4), tls_version(hello_version), cursor, 2U));
    cursor += 34U;
    if (cursor >= offset + length) return node;
    const auto session_length = static_cast<std::size_t>(frame.at(cursor++));
    if (cursor + session_length > offset + length) return node;
    cursor += session_length;
    if (handshake_type == 1U) {
        if (cursor + 2U > offset + length) return node;
        const auto cipher_length = static_cast<std::size_t>(u16(frame, cursor));
        cursor += 2U;
        if (cursor + cipher_length + 1U > offset + length) return node;
        node.fields.push_back(field(
            "cipher_suites", "", std::to_string(cipher_length / 2U) + " suites",
            cursor, cipher_length));
        cursor += cipher_length;
        const auto compression_length = static_cast<std::size_t>(frame.at(cursor++));
        if (cursor + compression_length > offset + length) return node;
        cursor += compression_length;
    } else {
        if (cursor + 3U > offset + length) return node;
        node.fields.push_back(field(
            "cipher_suite", hex(u16(frame, cursor), 4), hex(u16(frame, cursor), 4),
            cursor, 2U));
        cursor += 3U;
    }
    if (cursor + 2U > offset + length) return node;
    const auto extensions_length = static_cast<std::size_t>(u16(frame, cursor));
    cursor += 2U;
    const auto extensions_end = std::min(offset + length, cursor + extensions_length);
    while (cursor + 4U <= extensions_end) {
        const auto type = u16(frame, cursor);
        const auto extension_length = static_cast<std::size_t>(u16(frame, cursor + 2U));
        const auto data = cursor + 4U;
        if (data + extension_length > extensions_end) break;
        if (type == 0U && extension_length >= 5U) {
            const auto name_length = static_cast<std::size_t>(u16(frame, data + 3U));
            if (data + 5U + name_length <= data + extension_length) {
                const auto name = ascii(frame, data + 5U, name_length);
                node.fields.push_back(field(
                    "server_name", name, name, data + 5U, name_length));
            }
        } else if (type == 16U && extension_length >= 3U) {
            const auto protocol_length = static_cast<std::size_t>(frame.at(data + 2U));
            if (data + 3U + protocol_length <= data + extension_length) {
                const auto protocol = ascii(frame, data + 3U, protocol_length);
                node.fields.push_back(field(
                    "alpn", protocol, protocol, data + 3U, protocol_length));
            }
        }
        cursor = data + extension_length;
    }
    return node;
}

}  // namespace

std::optional<protocol_node> parse_udp_application(
    const packet::byte_view frame,
    const std::size_t payload_offset,
    const std::size_t payload_length,
    const std::uint16_t source_port,
    const std::uint16_t destination_port) {
    if (payload_offset > frame.size() || payload_length > frame.size() - payload_offset) {
        return std::nullopt;
    }
    if (source_port == 53U || destination_port == 53U ||
        source_port == 5353U || destination_port == 5353U) {
        return parse_dns(frame, payload_offset, payload_length);
    }
    if ((source_port == 67U || source_port == 68U) &&
        (destination_port == 67U || destination_port == 68U)) {
        return parse_dhcp(frame, payload_offset, payload_length);
    }
    return std::nullopt;
}

std::optional<protocol_node> parse_tcp_application(
    const packet::byte_view frame,
    const std::size_t payload_offset,
    const std::size_t payload_length,
    const std::uint16_t source_port,
    const std::uint16_t destination_port) {
    if (payload_offset > frame.size() || payload_length > frame.size() - payload_offset ||
        payload_length == 0U) {
        return std::nullopt;
    }
    const auto preview_length = std::min(payload_length, std::size_t{16U});
    const auto preview = ascii(frame, payload_offset, preview_length);
    if (source_port == 80U || destination_port == 80U || source_port == 8080U ||
        destination_port == 8080U || looks_like_http(preview)) {
        if (looks_like_http(preview)) {
            return parse_http(frame, payload_offset, payload_length);
        }
    }
    const bool tls_signature = payload_length >= 3U &&
        frame.at(payload_offset) >= 20U && frame.at(payload_offset) <= 23U &&
        frame.at(payload_offset + 1U) == 3U;
    if ((source_port == 443U || destination_port == 443U || tls_signature) && tls_signature) {
        return parse_tls(frame, payload_offset, payload_length);
    }
    return std::nullopt;
}

}  // namespace netscope::protocol
