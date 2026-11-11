#pragma once

#include "netscope/analysis/tcp_flow.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace netscope::packet {
struct packet_record;
}

namespace netscope::analysis {

struct anomaly_config {
    std::size_t port_scan_unique_ports{20U};
    std::chrono::seconds port_scan_window{10};
    std::uint64_t retransmission_minimum_packets{10U};
    double retransmission_ratio{0.20};
};

struct anomaly_alert {
    std::string rule;
    std::string title;
    std::string evidence;
    std::optional<std::uint64_t> packet_number;
    std::optional<std::uint64_t> flow_id;
};

class anomaly_detector final {
public:
    explicit anomaly_detector(anomaly_config config = {});

    [[nodiscard]] std::vector<anomaly_alert> ingest(
        std::shared_ptr<const packet::packet_record> packet);
    [[nodiscard]] std::vector<anomaly_alert> evaluate_flows(
        const std::vector<tcp_flow_snapshot>& flows) const;
    void clear();

private:
    struct port_event {
        std::chrono::system_clock::time_point timestamp;
        std::uint16_t destination_port{0U};
    };

    anomaly_config config_;
    std::map<std::string, std::deque<port_event>> syn_events_;
    std::map<std::string, std::chrono::system_clock::time_point> last_scan_alert_;
};

}  // namespace netscope::analysis
