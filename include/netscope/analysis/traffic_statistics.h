#pragma once

#include <cstdint>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace netscope::packet {
struct packet_record;
}

namespace netscope::analysis {

struct traffic_snapshot {
    std::uint64_t total_packets{0U};
    std::uint64_t total_bytes{0U};
    double packet_rate{0.0};
    double byte_rate{0.0};
    std::map<std::string, std::uint64_t> protocol_counts;
    std::map<std::string, std::uint64_t> host_counts;
    std::map<std::uint16_t, std::uint64_t> port_counts;
    std::map<std::string, std::uint64_t> length_buckets;
};

class traffic_statistics final {
public:
    void ingest(std::shared_ptr<const packet::packet_record> packet);
    [[nodiscard]] traffic_snapshot snapshot() const;
    void clear();

private:
    mutable std::mutex mutex_;
    traffic_snapshot totals_;
    std::optional<std::chrono::system_clock::time_point> first_time_;
    std::optional<std::chrono::system_clock::time_point> last_time_;
};

}  // namespace netscope::analysis
