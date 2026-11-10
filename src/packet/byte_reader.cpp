#include "netscope/packet/byte_reader.h"

#include <algorithm>
#include <sstream>
#include <string>

namespace netscope::packet {
namespace {

std::string make_parse_error_message(
    const std::size_t offset,
    const std::size_t requested,
    const std::size_t available) {
    std::ostringstream message;
    message << "packet data truncated at offset " << offset << ": requested "
            << requested << " byte(s), available " << available;
    return message.str();
}

}  // namespace

parse_error::parse_error(
    const std::size_t offset,
    const std::size_t requested,
    const std::size_t available)
    : std::runtime_error{make_parse_error_message(offset, requested, available)},
      offset_{offset},
      requested_{requested},
      available_{available} {}

std::size_t parse_error::offset() const noexcept {
    return offset_;
}

std::size_t parse_error::requested() const noexcept {
    return requested_;
}

std::size_t parse_error::available() const noexcept {
    return available_;
}

byte_view::byte_view(const std::uint8_t* const data, const std::size_t size) noexcept
    : data_{data}, size_{data == nullptr ? 0U : size} {}

byte_view::byte_view(const std::vector<std::uint8_t>& bytes) noexcept
    : byte_view{bytes.data(), bytes.size()} {}

const std::uint8_t* byte_view::data() const noexcept {
    return data_;
}

std::size_t byte_view::size() const noexcept {
    return size_;
}

bool byte_view::empty() const noexcept {
    return size_ == 0U;
}

std::uint8_t byte_view::at(const std::size_t index) const {
    if (index >= size_) {
        throw parse_error{index, 1U, 0U};
    }
    return data_[index];
}

byte_view byte_view::subview(
    const std::size_t offset,
    const std::size_t count) const {
    if (offset > size_) {
        throw parse_error{offset, count, 0U};
    }

    const auto available = size_ - offset;
    if (count > available) {
        throw parse_error{offset, count, available};
    }

    return byte_view{data_ + offset, count};
}

byte_reader::byte_reader(const byte_view bytes) noexcept : bytes_{bytes} {}

std::size_t byte_reader::position() const noexcept {
    return position_;
}

std::size_t byte_reader::remaining() const noexcept {
    return bytes_.size() - position_;
}

std::uint8_t byte_reader::read_u8() {
    const auto value = bytes_.at(position_);
    ++position_;
    return value;
}

std::uint16_t byte_reader::read_u16_be() {
    const auto bytes = read_bytes(2U);
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes.at(0)) << 8U) |
        static_cast<std::uint16_t>(bytes.at(1)));
}

std::uint16_t byte_reader::read_u16_le() {
    const auto bytes = read_bytes(2U);
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(bytes.at(0)) |
        (static_cast<std::uint16_t>(bytes.at(1)) << 8U));
}

std::uint32_t byte_reader::read_u32_be() {
    const auto bytes = read_bytes(4U);
    return (static_cast<std::uint32_t>(bytes.at(0)) << 24U) |
           (static_cast<std::uint32_t>(bytes.at(1)) << 16U) |
           (static_cast<std::uint32_t>(bytes.at(2)) << 8U) |
           static_cast<std::uint32_t>(bytes.at(3));
}

std::uint32_t byte_reader::read_u32_le() {
    const auto bytes = read_bytes(4U);
    return static_cast<std::uint32_t>(bytes.at(0)) |
           (static_cast<std::uint32_t>(bytes.at(1)) << 8U) |
           (static_cast<std::uint32_t>(bytes.at(2)) << 16U) |
           (static_cast<std::uint32_t>(bytes.at(3)) << 24U);
}

byte_view byte_reader::read_bytes(const std::size_t count) {
    const auto result = bytes_.subview(position_, count);
    position_ += count;
    return result;
}

void byte_reader::skip(const std::size_t count) {
    static_cast<void>(read_bytes(count));
}

}  // namespace netscope::packet

