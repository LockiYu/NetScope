#include "netscope/capture/packet_merger.h"

#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <utility>

namespace netscope::capture {

packet_merger::packet_merger(
    const std::chrono::microseconds merge_window,
    const bool deduplicate)
    : merge_window_{merge_window}, deduplicate_{deduplicate} {
    if (merge_window_ < std::chrono::microseconds::zero()) {
        throw std::invalid_argument{"merge window must not be negative"};
    }
}

void packet_merger::push(interface_packet packet) {
    pending_.push_back(std::move(packet));
}

std::vector<merged_packet> packet_merger::drain_ready(
    const std::chrono::system_clock::time_point latest_time) {
    const auto cutoff = latest_time - merge_window_;
    std::vector<interface_packet> ready;
    std::vector<interface_packet> retained;
    ready.reserve(pending_.size());
    retained.reserve(pending_.size());

    for (auto& packet : pending_) {
        if (packet.packet.timestamp <= cutoff) {
            ready.push_back(std::move(packet));
        } else {
            retained.push_back(std::move(packet));
        }
    }
    pending_ = std::move(retained);
    return merge(std::move(ready));
}

std::vector<merged_packet> packet_merger::flush_all() {
    auto packets = std::move(pending_);
    pending_.clear();
    return merge(std::move(packets));
}

std::size_t packet_merger::pending_count() const noexcept {
    return pending_.size();
}

std::vector<merged_packet> packet_merger::merge(
    std::vector<interface_packet> packets) const {
    std::stable_sort(packets.begin(), packets.end(), [](const auto& left, const auto& right) {
        return left.packet.timestamp < right.packet.timestamp;
    });

    std::vector<merged_packet> result;
    result.reserve(packets.size());
    for (auto& candidate : packets) {
        bool merged{false};
        if (deduplicate_) {
            for (auto existing = result.rbegin(); existing != result.rend(); ++existing) {
                const auto difference = candidate.packet.timestamp - existing->packet.timestamp;
                if (difference > merge_window_) {
                    break;
                }
                const bool different_interface = std::find(
                    existing->interfaces.begin(), existing->interfaces.end(),
                    candidate.interface_name) == existing->interfaces.end();
                const bool same_packet =
                    candidate.packet.captured_length == existing->packet.captured_length &&
                    candidate.packet.original_length == existing->packet.original_length &&
                    candidate.packet.bytes == existing->packet.bytes;
                if (different_interface && same_packet) {
                    existing->interfaces.push_back(std::move(candidate.interface_name));
                    merged = true;
                    break;
                }
            }
        }
        if (!merged) {
            result.push_back(merged_packet{
                std::move(candidate.packet),
                {std::move(candidate.interface_name)},
            });
        }
    }
    return result;
}

}  // namespace netscope::capture

