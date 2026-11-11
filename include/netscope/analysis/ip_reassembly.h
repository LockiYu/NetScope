#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace netscope::packet {
struct packet_record;
}

namespace netscope::analysis {

struct reassembled_datagram {
    std::uint8_t version{0};
    std::string source;
    std::string destination;
    std::uint32_t identification{0};
    std::uint8_t next_header{0};
    std::vector<std::uint8_t> payload;
    std::size_t fragment_count{0};
    std::size_t overlapping_bytes{0};
    std::vector<std::uint64_t> packet_numbers;
};

class ip_reassembler final {
public:
    [[nodiscard]] std::optional<reassembled_datagram> ingest(
        std::shared_ptr<const packet::packet_record> packet);
    [[nodiscard]] std::size_t pending_count() const noexcept;
    void clear() noexcept;

private:
    struct fragment_key {
        std::uint8_t version{0};
        std::string source;
        std::string destination;
        std::uint32_t identification{0};
        std::uint8_t next_header{0};

        [[nodiscard]] bool operator<(const fragment_key& other) const noexcept;
    };

    struct partial_datagram {
        std::vector<std::uint8_t> bytes;
        std::vector<bool> present;
        std::optional<std::size_t> total_size;
        std::size_t fragment_count{0};
        std::size_t overlapping_bytes{0};
        std::vector<std::uint64_t> packet_numbers;
    };

    std::map<fragment_key, partial_datagram> pending_;
};

}  // namespace netscope::analysis
