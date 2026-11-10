#pragma once

#include "netscope/capture/pcap_file.h"

#include <chrono>
#include <string>
#include <vector>

namespace netscope::capture {

struct interface_packet {
    std::string interface_name;
    captured_packet packet;
};

struct merged_packet {
    captured_packet packet;
    std::vector<std::string> interfaces;
};

class packet_merger final {
public:
    explicit packet_merger(
        std::chrono::microseconds merge_window = std::chrono::microseconds{500},
        bool deduplicate = true);

    void push(interface_packet packet);
    [[nodiscard]] std::vector<merged_packet> drain_ready(
        std::chrono::system_clock::time_point latest_time);
    [[nodiscard]] std::vector<merged_packet> flush_all();
    [[nodiscard]] std::size_t pending_count() const noexcept;

private:
    [[nodiscard]] std::vector<merged_packet> merge(
        std::vector<interface_packet> packets) const;

    std::chrono::microseconds merge_window_;
    bool deduplicate_;
    std::vector<interface_packet> pending_;
};

}  // namespace netscope::capture

