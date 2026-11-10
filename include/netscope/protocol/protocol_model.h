#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace netscope::protocol {

struct byte_range {
    std::size_t offset{0};
    std::size_t length{0};

    [[nodiscard]] bool contains(std::size_t byte_offset) const noexcept;
};

enum class validation_status {
    not_checked,
    valid,
    invalid,
    warning,
};

struct protocol_field {
    std::string name;
    std::string raw_value;
    std::string display_value;
    byte_range bytes;
    std::optional<std::uint8_t> bit_offset;
    std::optional<std::uint8_t> bit_length;
    validation_status validation{validation_status::not_checked};
    std::vector<std::string> warnings;
};

struct protocol_node {
    std::string name;
    byte_range bytes;
    std::vector<protocol_field> fields;
    std::vector<protocol_node> children;
    std::vector<std::string> warnings;
};

[[nodiscard]] std::string to_json(const protocol_node& node);

}  // namespace netscope::protocol

