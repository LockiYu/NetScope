#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace netscope::packet {

class parse_error final : public std::runtime_error {
public:
    parse_error(std::size_t offset, std::size_t requested, std::size_t available);

    [[nodiscard]] std::size_t offset() const noexcept;
    [[nodiscard]] std::size_t requested() const noexcept;
    [[nodiscard]] std::size_t available() const noexcept;

private:
    std::size_t offset_;
    std::size_t requested_;
    std::size_t available_;
};

class byte_view final {
public:
    byte_view(const std::uint8_t* data, std::size_t size) noexcept;
    explicit byte_view(const std::vector<std::uint8_t>& bytes) noexcept;

    [[nodiscard]] const std::uint8_t* data() const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] std::uint8_t at(std::size_t index) const;
    [[nodiscard]] byte_view subview(std::size_t offset, std::size_t count) const;

private:
    const std::uint8_t* data_;
    std::size_t size_;
};

class byte_reader final {
public:
    explicit byte_reader(byte_view bytes) noexcept;

    [[nodiscard]] std::size_t position() const noexcept;
    [[nodiscard]] std::size_t remaining() const noexcept;
    [[nodiscard]] std::uint8_t read_u8();
    [[nodiscard]] std::uint16_t read_u16_be();
    [[nodiscard]] std::uint16_t read_u16_le();
    [[nodiscard]] std::uint32_t read_u32_be();
    [[nodiscard]] std::uint32_t read_u32_le();
    [[nodiscard]] byte_view read_bytes(std::size_t count);
    void skip(std::size_t count);

private:
    byte_view bytes_;
    std::size_t position_{0};
};

}  // namespace netscope::packet

