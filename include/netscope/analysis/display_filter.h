#pragma once

#include <cstddef>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace netscope::packet {
struct packet_record;
}

namespace netscope::analysis {

class filter_error final : public std::runtime_error {
public:
    filter_error(std::string message, std::size_t position);
    [[nodiscard]] std::size_t position() const noexcept;

private:
    std::size_t position_;
};

class display_filter final {
public:
    explicit display_filter(std::string_view expression);
    [[nodiscard]] bool matches(const packet::packet_record& packet) const;

private:
    std::function<bool(const packet::packet_record&)> predicate_;
};

}  // namespace netscope::analysis
