#include "netscope/analysis/display_filter.h"

#include "netscope/packet/packet_repository.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace netscope::analysis {
namespace {

enum class token_kind {
    end,
    word,
    string,
    left_parenthesis,
    right_parenthesis,
    equal,
    not_equal,
    greater,
    greater_equal,
    less,
    less_equal,
};

struct token {
    token_kind kind{token_kind::end};
    std::string text;
    std::size_t position{0U};
};

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

class lexer final {
public:
    explicit lexer(const std::string_view input) : input_{input} {}

    token next() {
        while (cursor_ < input_.size() &&
               std::isspace(static_cast<unsigned char>(input_[cursor_])) != 0) {
            ++cursor_;
        }
        if (cursor_ == input_.size()) {
            return token{token_kind::end, {}, cursor_};
        }
        const auto start = cursor_;
        const char current = input_[cursor_++];
        if (current == '(') {
            return token{token_kind::left_parenthesis, "(", start};
        }
        if (current == ')') {
            return token{token_kind::right_parenthesis, ")", start};
        }
        if (current == '"' || current == '\'') {
            std::string value;
            while (cursor_ < input_.size() && input_[cursor_] != current) {
                if (input_[cursor_] == '\\' && cursor_ + 1U < input_.size()) {
                    ++cursor_;
                }
                value.push_back(input_[cursor_++]);
            }
            if (cursor_ == input_.size()) {
                throw filter_error{"unterminated string literal", start};
            }
            ++cursor_;
            return token{token_kind::string, std::move(value), start};
        }
        if (current == '=' || current == '!' || current == '>' || current == '<') {
            const bool has_equal = cursor_ < input_.size() && input_[cursor_] == '=';
            if (has_equal) {
                ++cursor_;
            }
            if (current == '=' && !has_equal) {
                throw filter_error{"use == for equality", start};
            }
            if (current == '!' && !has_equal) {
                throw filter_error{"use != for inequality", start};
            }
            const auto kind = current == '=' ? token_kind::equal
                : current == '!' ? token_kind::not_equal
                : current == '>' ? (has_equal ? token_kind::greater_equal : token_kind::greater)
                : (has_equal ? token_kind::less_equal : token_kind::less);
            return token{kind, std::string{input_.substr(start, cursor_ - start)}, start};
        }

        while (cursor_ < input_.size()) {
            const char next = input_[cursor_];
            if (std::isspace(static_cast<unsigned char>(next)) != 0 || next == '(' ||
                next == ')' || next == '=' || next == '!' || next == '>' || next == '<') {
                break;
            }
            ++cursor_;
        }
        return token{
            token_kind::word,
            std::string{input_.substr(start, cursor_ - start)},
            start,
        };
    }

private:
    std::string_view input_;
    std::size_t cursor_{0U};
};

const protocol::protocol_node* find_node(
    const protocol::protocol_node& node,
    const std::string& protocol_name) {
    const auto name = lowercase(node.name);
    const bool matches =
        (protocol_name == "frame" && name == "frame") ||
        ((protocol_name == "eth" || protocol_name == "ethernet") &&
         name == "ethernet ii") ||
        (protocol_name == "arp" && name == "address resolution protocol") ||
        ((protocol_name == "ip" || protocol_name == "ipv4") &&
         name == "internet protocol version 4") ||
        ((protocol_name == "ip" || protocol_name == "ipv6") &&
         name == "internet protocol version 6") ||
        (protocol_name == "tcp" && name == "transmission control protocol") ||
        (protocol_name == "udp" && name == "user datagram protocol") ||
        (protocol_name == "icmp" && name == "internet control message protocol") ||
        (protocol_name == "icmpv6" && name == "internet control message protocol v6") ||
        (protocol_name == "dns" && name == "domain name system") ||
        (protocol_name == "dhcp" && name == "dynamic host configuration protocol") ||
        (protocol_name == "http" && name == "hypertext transfer protocol") ||
        (protocol_name == "tls" && name == "transport layer security") ||
        name == protocol_name;
    if (matches) {
        return &node;
    }
    for (const auto& child : node.children) {
        if (const auto* found = find_node(child, protocol_name); found != nullptr) {
            return found;
        }
    }
    return nullptr;
}

const protocol::protocol_field* find_field(
    const protocol::protocol_node& node,
    const std::string& name) {
    const auto match = std::find_if(node.fields.begin(), node.fields.end(), [&](const auto& item) {
        return item.name == name;
    });
    return match == node.fields.end() ? nullptr : &*match;
}

std::string field_alias(std::string name) {
    if (name == "src") {
        return "source_address";
    }
    if (name == "dst") {
        return "destination_address";
    }
    if (name == "srcport") {
        return "source_port";
    }
    if (name == "dstport") {
        return "destination_port";
    }
    return name;
}

std::vector<std::string> resolve_values(
    const packet::packet_record& packet,
    const std::string& identifier) {
    const auto dot = identifier.find('.');
    if (dot == std::string::npos) {
        if (identifier == "process" || identifier == "proc") {
            if (!packet.process.has_value()) {
                return {};
            }
            return {packet.process->name, std::to_string(packet.process->pid)};
        }
        // Wireshark-compatible "frame contains" and "<protocol> contains"
        // search the raw bytes of the frame or of the matching protocol layer.
        const auto& bytes = packet.capture.packet.bytes;
        if (identifier == "frame") {
            return {std::string{bytes.begin(), bytes.end()}};
        }
        if (const auto* node = find_node(packet.analysis, identifier); node != nullptr) {
            if (node->bytes.offset < bytes.size()) {
                const auto available = bytes.size() - node->bytes.offset;
                const auto length = std::min(node->bytes.length, available);
                return {std::string{
                    bytes.begin() + static_cast<std::ptrdiff_t>(node->bytes.offset),
                    bytes.begin() + static_cast<std::ptrdiff_t>(node->bytes.offset + length)}};
            }
        }
        return {};
    }
    const auto prefix = lowercase(identifier.substr(0U, dot));
    const auto suffix = lowercase(identifier.substr(dot + 1U));
    if (prefix == "frame" && suffix == "len") {
        return {std::to_string(packet.capture.packet.captured_length)};
    }
    if (prefix == "frame" && suffix == "number") {
        return {std::to_string(packet.number)};
    }
    if (prefix == "protocol") {
        return {packet.protocol};
    }
    if ((prefix == "process" || prefix == "proc") && packet.process.has_value()) {
        if (suffix == "name") {
            return {packet.process->name};
        }
        if (suffix == "pid") {
            return {std::to_string(packet.process->pid)};
        }
    }
    if ((prefix == "ip" || prefix == "ipv4" || prefix == "ipv6") && suffix == "src") {
        return {packet.source};
    }
    if ((prefix == "ip" || prefix == "ipv4" || prefix == "ipv6") && suffix == "dst") {
        return {packet.destination};
    }
    if ((prefix == "ip" || prefix == "ipv4" || prefix == "ipv6") &&
        (suffix == "addr" || suffix == "host")) {
        return {packet.source, packet.destination};
    }
    if ((prefix == "tcp" || prefix == "udp") && suffix == "port") {
        const auto* transport = find_node(packet.analysis, prefix);
        if (transport == nullptr) {
            return {};
        }
        std::vector<std::string> ports;
        for (const auto* const name : {"source_port", "destination_port"}) {
            if (const auto* field = find_field(*transport, name); field != nullptr) {
                if (!field->raw_value.empty()) {
                    ports.push_back(field->raw_value);
                }
                ports.push_back(field->display_value);
            }
        }
        return ports;
    }
    if (prefix == "tcp" && suffix.rfind("flags.", 0U) == 0U) {
        const auto* tcp = find_node(packet.analysis, "tcp");
        const auto* flags = tcp == nullptr ? nullptr : find_field(*tcp, "flags");
        if (flags == nullptr) {
            return {};
        }
        const auto text = lowercase(flags->display_value);
        const auto flag = suffix.substr(6U);
        const bool set = text.find(flag) != std::string::npos;
        return {set ? "1" : "0"};
    }
    if (prefix == "eth" &&
        (suffix == "src" || suffix == "dst" || suffix == "addr")) {
        const auto* ethernet = find_node(packet.analysis, "eth");
        if (ethernet == nullptr) {
            return {};
        }
        const auto* source = find_field(*ethernet, "source");
        const auto* destination = find_field(*ethernet, "destination");
        std::vector<std::string> addresses;
        if (suffix != "dst" && source != nullptr) {
            addresses.push_back(source->display_value);
        }
        if (suffix != "src" && destination != nullptr) {
            addresses.push_back(destination->display_value);
        }
        return addresses;
    }
    if (prefix == "dns") {
        const auto* dns = find_node(packet.analysis, "dns");
        if (dns == nullptr) {
            return {};
        }
        std::string field_name;
        if (suffix == "qry.name") field_name = "query_name";
        if (suffix == "qry.type") field_name = "query_type";
        if (suffix == "id") field_name = "transaction_id";
        if (suffix == "count.queries") field_name = "question_count";
        if (suffix == "count.answers") field_name = "answer_count";
        if (suffix == "flags.response") {
            const auto* flags = find_field(*dns, "flags");
            if (flags == nullptr) {
                return {};
            }
            return {lowercase(flags->display_value) == "response" ? "1" : "0"};
        }
        if (!field_name.empty()) {
            const auto* field = find_field(*dns, field_name);
            if (field == nullptr) {
                return {};
            }
            return {field->display_value};
        }
    }
    if (prefix == "http") {
        const auto* http = find_node(packet.analysis, "http");
        if (http == nullptr) {
            return {};
        }
        std::string field_name;
        if (suffix == "host") field_name = "host";
        if (suffix == "request.method") field_name = "method";
        if (suffix == "request.uri") field_name = "request_uri";
        if (suffix == "response.code") field_name = "status_code";
        if (!field_name.empty()) {
            const auto* field = find_field(*http, field_name);
            if (field == nullptr) {
                return {};
            }
            return {field->display_value};
        }
    }
    if (prefix == "tls") {
        const auto* tls = find_node(packet.analysis, "tls");
        if (tls == nullptr) {
            return {};
        }
        std::string field_name;
        if (suffix == "handshake.extensions_server_name") field_name = "server_name";
        if (suffix == "handshake.type") field_name = "handshake_type";
        if (!field_name.empty()) {
            const auto* field = find_field(*tls, field_name);
            if (field == nullptr) {
                return {};
            }
            return {field->display_value};
        }
    }

    const auto* node = find_node(packet.analysis, prefix);
    if (node == nullptr) {
        return {};
    }
    const auto* field = find_field(*node, field_alias(suffix));
    if (field == nullptr) {
        return {};
    }
    if (!field->raw_value.empty()) {
        return {field->raw_value, field->display_value};
    }
    return {field->display_value};
}

bool protocol_present(const packet::packet_record& packet, const std::string& identifier) {
    if (identifier == "protocol") {
        return !packet.protocol.empty();
    }
    if (identifier == "process" || identifier == "proc") {
        return packet.process.has_value();
    }
    if (identifier.find('.') != std::string::npos) {
        // A bare field name means "this field is present", as in Wireshark.
        return !resolve_values(packet, identifier).empty();
    }
    return find_node(packet.analysis, lowercase(identifier)) != nullptr;
}

std::optional<double> number_value(const std::string& text) {
    char* end{nullptr};
    const double value = std::strtod(text.c_str(), &end);
    if (end == text.c_str() || end == nullptr || *end != '\0') {
        return std::nullopt;
    }
    return value;
}

bool compare_value(
    const std::string& left,
    const token_kind operation,
    const std::string& right) {
    const auto left_number = number_value(left);
    const auto right_number = number_value(right);
    if (operation == token_kind::greater || operation == token_kind::greater_equal ||
        operation == token_kind::less || operation == token_kind::less_equal) {
        if (!left_number.has_value() || !right_number.has_value()) {
            return false;
        }
        if (operation == token_kind::greater) {
            return left_number.value() > right_number.value();
        }
        if (operation == token_kind::greater_equal) {
            return left_number.value() >= right_number.value();
        }
        if (operation == token_kind::less) {
            return left_number.value() < right_number.value();
        }
        return left_number.value() <= right_number.value();
    }
    const auto normalized_left = lowercase(left);
    const auto normalized_right = lowercase(right);
    const bool equal = normalized_left == normalized_right;
    return operation == token_kind::equal ? equal : !equal;
}

using predicate = std::function<bool(const packet::packet_record&)>;

class parser final {
public:
    explicit parser(const std::string_view input) : lexer_{input}, current_{lexer_.next()} {}

    predicate parse() {
        if (current_.kind == token_kind::end) {
            return [](const packet::packet_record&) { return true; };
        }
        auto result = parse_or();
        if (current_.kind != token_kind::end) {
            throw filter_error{"unexpected token '" + current_.text + "'", current_.position};
        }
        return result;
    }

private:
    void advance() { current_ = lexer_.next(); }

    bool keyword(const std::string& value) const {
        return current_.kind == token_kind::word && lowercase(current_.text) == value;
    }

    predicate parse_or() {
        auto left = parse_and();
        while (keyword("or")) {
            advance();
            auto right = parse_and();
            left = [left = std::move(left), right = std::move(right)](const auto& packet) {
                return left(packet) || right(packet);
            };
        }
        return left;
    }

    predicate parse_and() {
        auto left = parse_unary();
        while (keyword("and")) {
            advance();
            auto right = parse_unary();
            left = [left = std::move(left), right = std::move(right)](const auto& packet) {
                return left(packet) && right(packet);
            };
        }
        return left;
    }

    predicate parse_unary() {
        if (keyword("not")) {
            advance();
            auto operand = parse_unary();
            return [operand = std::move(operand)](const auto& packet) {
                return !operand(packet);
            };
        }
        if (current_.kind == token_kind::left_parenthesis) {
            advance();
            auto nested = parse_or();
            if (current_.kind != token_kind::right_parenthesis) {
                throw filter_error{"expected ')'", current_.position};
            }
            advance();
            return nested;
        }
        return parse_predicate();
    }

    predicate parse_predicate() {
        if (current_.kind != token_kind::word || keyword("and") || keyword("or")) {
            throw filter_error{"expected a protocol or field", current_.position};
        }
        const auto identifier = lowercase(current_.text);
        advance();
        if (current_.kind == token_kind::end ||
            current_.kind == token_kind::right_parenthesis || keyword("and") || keyword("or")) {
            return [identifier](const auto& packet) {
                return protocol_present(packet, identifier);
            };
        }

        const bool contains = keyword("contains");
        const auto operation = current_.kind;
        if (!contains && operation != token_kind::equal && operation != token_kind::not_equal &&
            operation != token_kind::greater && operation != token_kind::greater_equal &&
            operation != token_kind::less && operation != token_kind::less_equal) {
            throw filter_error{"expected a comparison operator", current_.position};
        }
        advance();
        if (current_.kind != token_kind::word && current_.kind != token_kind::string) {
            throw filter_error{"expected a comparison value", current_.position};
        }
        const auto expected = current_.text;
        advance();
        return [identifier, operation, contains, expected](const auto& packet) {
            const auto values = resolve_values(packet, identifier);
            return std::any_of(values.begin(), values.end(), [&](const auto& value) {
                if (contains) {
                    return lowercase(value).find(lowercase(expected)) != std::string::npos;
                }
                return compare_value(value, operation, expected);
            });
        };
    }

    lexer lexer_;
    token current_;
};

}  // namespace

filter_error::filter_error(std::string message, const std::size_t position)
    : std::runtime_error{std::move(message)}, position_{position} {}

std::size_t filter_error::position() const noexcept {
    return position_;
}

display_filter::display_filter(const std::string_view expression)
    : predicate_{parser{expression}.parse()} {}

bool display_filter::matches(const packet::packet_record& packet) const {
    return predicate_(packet);
}

}  // namespace netscope::analysis
