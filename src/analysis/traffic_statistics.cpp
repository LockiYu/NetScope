#include "netscope/analysis/traffic_statistics.h"

#include "netscope/packet/packet_repository.h"

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>

namespace netscope::analysis {
namespace {

const protocol::protocol_node* find_node(
    const protocol::protocol_node& node,
    const std::string& name) {
    if (node.name == name) {
        return &node;
    }
    for (const auto& child : node.children) {
        if (const auto* found = find_node(child, name); found != nullptr) {
            return found;
        }
    }
    return nullptr;
}

std::optional<std::uint16_t> port(
    const protocol::protocol_node* const node,
    const std::string& name) {
    if (node == nullptr) {
        return std::nullopt;
    }
    const auto found = std::find_if(node->fields.begin(), node->fields.end(), [&](const auto& field) {
        return field.name == name;
    });
    if (found == node->fields.end()) {
        return std::nullopt;
    }
    try {
        return static_cast<std::uint16_t>(std::stoul(found->raw_value));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::string length_bucket(const std::uint32_t length) {
    if (length <= 64U) return "0-64";
    if (length <= 127U) return "65-127";
    if (length <= 255U) return "128-255";
    if (length <= 511U) return "256-511";
    if (length <= 1023U) return "512-1023";
    if (length <= 1518U) return "1024-1518";
    return "1519+";
}

}  // namespace

void traffic_statistics::ingest(std::shared_ptr<const packet::packet_record> packet) {
    if (!packet) {
        return;
    }
    std::lock_guard lock{mutex_};
    ++totals_.total_packets;
    totals_.total_bytes += packet->capture.packet.original_length;
    ++totals_.protocol_counts[packet->protocol.empty() ? "Unknown" : packet->protocol];
    if (!packet->source.empty()) {
        ++totals_.host_counts[packet->source];
    }
    if (!packet->destination.empty()) {
        ++totals_.host_counts[packet->destination];
    }
    ++totals_.length_buckets[length_bucket(packet->capture.packet.original_length)];

    const auto* transport = find_node(packet->analysis, "Transmission Control Protocol");
    if (transport == nullptr) {
        transport = find_node(packet->analysis, "User Datagram Protocol");
    }
    if (const auto value = port(transport, "source_port"); value.has_value()) {
        ++totals_.port_counts[value.value()];
    }
    if (const auto value = port(transport, "destination_port"); value.has_value()) {
        ++totals_.port_counts[value.value()];
    }

    const auto timestamp = packet->capture.packet.timestamp;
    if (!first_time_.has_value() || timestamp < first_time_.value()) {
        first_time_ = timestamp;
    }
    if (!last_time_.has_value() || timestamp > last_time_.value()) {
        last_time_ = timestamp;
    }
}

traffic_snapshot traffic_statistics::snapshot() const {
    std::lock_guard lock{mutex_};
    auto result = totals_;
    if (first_time_.has_value() && last_time_.has_value()) {
        const double seconds = std::chrono::duration<double>(
            last_time_.value() - first_time_.value()).count();
        if (seconds > 0.0) {
            result.packet_rate = static_cast<double>(result.total_packets) / seconds;
            result.byte_rate = static_cast<double>(result.total_bytes) / seconds;
        }
    }
    return result;
}

void traffic_statistics::clear() {
    std::lock_guard lock{mutex_};
    totals_ = {};
    first_time_.reset();
    last_time_.reset();
}

}  // namespace netscope::analysis
