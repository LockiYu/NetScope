#include "netscope/analysis/anomaly_detector.h"

#include "netscope/packet/packet_repository.h"

#include <algorithm>
#include <set>
#include <stdexcept>

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

const protocol::protocol_field* find_field(
    const protocol::protocol_node& node,
    const std::string& name) {
    const auto found = std::find_if(node.fields.begin(), node.fields.end(), [&](const auto& item) {
        return item.name == name;
    });
    return found == node.fields.end() ? nullptr : &*found;
}

const protocol::protocol_field* find_field_recursive(
    const protocol::protocol_node& node,
    const std::string& name) {
    if (const auto* found = find_field(node, name); found != nullptr) {
        return found;
    }
    for (const auto& child : node.children) {
        if (const auto* found = find_field_recursive(child, name); found != nullptr) {
            return found;
        }
    }
    return nullptr;
}

std::optional<std::string> first_warning(const protocol::protocol_node& node) {
    const auto actionable = [](const std::string& warning) {
        return warning.find("checksum mismatch") == std::string::npos;
    };
    const auto node_warning = std::find_if(
        node.warnings.begin(), node.warnings.end(), actionable);
    if (node_warning != node.warnings.end()) {
        return *node_warning;
    }
    for (const auto& field : node.fields) {
        const auto field_warning = std::find_if(
            field.warnings.begin(), field.warnings.end(), actionable);
        if (field_warning != field.warnings.end()) {
            return *field_warning;
        }
    }
    for (const auto& child : node.children) {
        if (auto warning = first_warning(child); warning.has_value()) {
            return warning;
        }
    }
    return std::nullopt;
}

std::optional<std::uint32_t> numeric_field(
    const protocol::protocol_node& node,
    const std::string& name) {
    const auto* value = find_field(node, name);
    if (value == nullptr) {
        return std::nullopt;
    }
    try {
        return static_cast<std::uint32_t>(std::stoul(value->raw_value, nullptr, 0));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

}  // namespace

anomaly_detector::anomaly_detector(anomaly_config config) : config_{config} {
    if (config_.port_scan_unique_ports == 0U ||
        config_.port_scan_window <= std::chrono::seconds::zero() ||
        config_.retransmission_ratio < 0.0 || config_.retransmission_ratio > 1.0) {
        throw std::invalid_argument{"invalid anomaly detector configuration"};
    }
}

std::vector<anomaly_alert> anomaly_detector::ingest(
    std::shared_ptr<const packet::packet_record> packet) {
    std::vector<anomaly_alert> alerts;
    if (!packet) {
        return alerts;
    }

    if (const auto warning = first_warning(packet->analysis); warning.has_value()) {
        alerts.push_back(anomaly_alert{
            "malformed_packet",
            "Malformed or incomplete packet observation",
            warning.value(),
            packet->number,
            std::nullopt,
        });
    }
    if (find_field_recursive(packet->analysis, "header_authorization") != nullptr ||
        find_field_recursive(packet->analysis, "header_proxy-authorization") != nullptr) {
        alerts.push_back(anomaly_alert{
            "cleartext_authentication_field",
            "Cleartext HTTP authentication field observed",
            "An HTTP Authorization field name was present; its value is intentionally redacted.",
            packet->number,
            std::nullopt,
        });
    }

    const auto* tcp = find_node(packet->analysis, "Transmission Control Protocol");
    if (tcp == nullptr || packet->source.empty()) {
        return alerts;
    }
    const auto flags = numeric_field(*tcp, "flags");
    const auto destination_port = numeric_field(*tcp, "destination_port");
    if (!flags.has_value() || !destination_port.has_value() ||
        (flags.value() & 0x002U) == 0U || (flags.value() & 0x010U) != 0U) {
        return alerts;
    }

    const auto now = packet->capture.packet.timestamp;
    auto& events = syn_events_[packet->source];
    while (!events.empty() && now - events.front().timestamp > config_.port_scan_window) {
        events.pop_front();
    }
    events.push_back(port_event{now, static_cast<std::uint16_t>(destination_port.value())});
    std::set<std::uint16_t> unique_ports;
    for (const auto& event : events) {
        unique_ports.insert(event.destination_port);
    }
    const auto last_alert = last_scan_alert_.find(packet->source);
    const bool already_alerted = last_alert != last_scan_alert_.end() &&
        now - last_alert->second <= config_.port_scan_window;
    if (unique_ports.size() >= config_.port_scan_unique_ports && !already_alerted) {
        alerts.push_back(anomaly_alert{
            "port_scan_observation",
            "Possible port scan activity",
            packet->source + " contacted " + std::to_string(unique_ports.size()) +
                " unique destination ports within " +
                std::to_string(config_.port_scan_window.count()) + " seconds.",
            packet->number,
            std::nullopt,
        });
        last_scan_alert_[packet->source] = now;
    }
    return alerts;
}

std::vector<anomaly_alert> anomaly_detector::evaluate_flows(
    const std::vector<tcp_flow_snapshot>& flows) const {
    std::vector<anomaly_alert> alerts;
    for (const auto& flow : flows) {
        if (flow.packet_count < config_.retransmission_minimum_packets) {
            continue;
        }
        const double ratio = static_cast<double>(flow.retransmissions) /
            static_cast<double>(flow.packet_count);
        if (ratio > config_.retransmission_ratio) {
            alerts.push_back(anomaly_alert{
                "high_tcp_retransmission_ratio",
                "High TCP retransmission ratio",
                "Flow " + std::to_string(flow.id) + " has " +
                    std::to_string(flow.retransmissions) + " retransmissions across " +
                    std::to_string(flow.packet_count) + " packets.",
                std::nullopt,
                flow.id,
            });
        }
    }
    return alerts;
}

void anomaly_detector::clear() {
    syn_events_.clear();
    last_scan_alert_.clear();
}

}  // namespace netscope::analysis
