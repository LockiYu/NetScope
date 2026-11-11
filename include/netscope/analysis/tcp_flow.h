#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace netscope::packet {
struct packet_record;
}

namespace netscope::analysis {

enum class tcp_flow_state {
    opening,
    established,
    half_closed,
    closed,
    reset,
};

struct tcp_endpoint {
    std::string address;
    std::uint16_t port{0U};
};

struct tcp_flow_snapshot {
    std::uint64_t id{0U};
    tcp_endpoint client;
    tcp_endpoint server;
    tcp_flow_state state{tcp_flow_state::opening};
    std::uint64_t packet_count{0U};
    std::uint64_t byte_count{0U};
    std::uint64_t retransmissions{0U};
    std::uint64_t out_of_order_segments{0U};
    std::uint64_t duplicate_acknowledgements{0U};
    std::optional<std::chrono::microseconds> round_trip_time;
    std::vector<std::uint64_t> packet_numbers;
    std::vector<std::uint8_t> client_to_server_data;
    std::vector<std::uint8_t> server_to_client_data;
};

class tcp_flow_tracker final {
public:
    tcp_flow_tracker();
    ~tcp_flow_tracker();

    tcp_flow_tracker(const tcp_flow_tracker&) = delete;
    tcp_flow_tracker& operator=(const tcp_flow_tracker&) = delete;
    tcp_flow_tracker(tcp_flow_tracker&&) noexcept;
    tcp_flow_tracker& operator=(tcp_flow_tracker&&) noexcept;

    [[nodiscard]] std::optional<std::uint64_t> ingest(
        std::shared_ptr<const packet::packet_record> packet);
    [[nodiscard]] std::vector<tcp_flow_snapshot> snapshot() const;
    void clear();

private:
    class implementation;
    std::unique_ptr<implementation> implementation_;
};

}  // namespace netscope::analysis
