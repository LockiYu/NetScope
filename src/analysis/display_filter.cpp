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
    if ((prefix == "ip" || prefix == "ipv4" || prefix == "ipv6") && suffix == "src") {
        return {packet.source};
    }
    if ((prefix == "ip" || prefix == "ipv4" || prefix == "ipv6") && suffix == "dst") {
        return {packet.destination};
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
