#include "netscope/packet/packet_repository.h"

#include "netscope/packet/byte_reader.h"
#include "netscope/protocol/packet_parser.h"

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace netscope::packet {
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
    const auto found = std::find_if(
        node.fields.begin(), node.fields.end(), [&name](const auto& field) {
            return field.name == name;
        });
    return found == node.fields.end() ? nullptr : &*found;
}

std::string field_value(
    const protocol::protocol_node* node,
    const std::string& name) {
    if (node == nullptr) {
        return {};
    }
    const auto* value = find_field(*node, name);
    return value == nullptr ? std::string{} : value->display_value;
}

void summarize(packet_record& record) {
    const auto* ipv4 = find_node(record.analysis, "Internet Protocol Version 4");
    const auto* ipv6 = find_node(record.analysis, "Internet Protocol Version 6");
    const auto* network = ipv4 != nullptr ? ipv4 : ipv6;
    record.source = field_value(network, "source_address");
    record.destination = field_value(network, "destination_address");

    const auto* tcp = find_node(record.analysis, "Transmission Control Protocol");
    const auto* udp = find_node(record.analysis, "User Datagram Protocol");
    const auto* icmp = find_node(record.analysis, "Internet Control Message Protocol");
    const auto* icmpv6 = find_node(record.analysis, "Internet Control Message Protocol v6");
    const auto* arp = find_node(record.analysis, "Address Resolution Protocol");

    if (tcp != nullptr) {
        record.protocol = "TCP";
        record.information = field_value(tcp, "source_port") + " → " +
                             field_value(tcp, "destination_port") + " [" +
                             field_value(tcp, "flags") + ']';
    } else if (udp != nullptr) {
        record.protocol = "UDP";
        record.information = field_value(udp, "source_port") + " → " +
                             field_value(udp, "destination_port");
    } else if (icmp != nullptr) {
        record.protocol = "ICMP";
        record.information = field_value(icmp, "type");
    } else if (icmpv6 != nullptr) {
        record.protocol = "ICMPv6";
        record.information = field_value(icmpv6, "type");
    } else if (arp != nullptr) {
        record.protocol = "ARP";
        record.source = field_value(arp, "sender_ip");
        record.destination = field_value(arp, "target_ip");
        record.information = field_value(arp, "operation");
    } else {
        record.protocol = "Unknown";
        record.information = record.analysis.warnings.empty()
            ? std::string{"Unrecognized frame"}
            : record.analysis.warnings.front();
    }
}

}  // namespace

packet_repository::packet_repository(const std::size_t capacity) : capacity_{capacity} {
    if (capacity_ == 0U) {
        throw std::invalid_argument{"packet repository capacity must be positive"};
    }
}

std::shared_ptr<const packet_record> packet_repository::append(
    capture::merged_packet packet) {
    auto record = std::make_shared<packet_record>();
    record->capture = std::move(packet);
    record->analysis = protocol::parse_ethernet_frame(
        byte_view{record->capture.packet.bytes});
    summarize(*record);

    std::lock_guard<std::mutex> lock{mutex_};
    record->number = next_number_++;
    records_.push_back(record);
    if (records_.size() > capacity_) {
        records_.pop_front();
        ++evicted_count_;
    }
    return record;
}

std::shared_ptr<const packet_record> packet_repository::at(const std::size_t index) const {
    std::lock_guard<std::mutex> lock{mutex_};
    if (index >= records_.size()) {
        throw std::out_of_range{"packet repository index out of range"};
    }
    return records_[index];
}

std::vector<std::shared_ptr<const packet_record>> packet_repository::snapshot() const {
    std::lock_guard<std::mutex> lock{mutex_};
    return {records_.begin(), records_.end()};
}

std::size_t packet_repository::size() const {
    std::lock_guard<std::mutex> lock{mutex_};
    return records_.size();
}

std::size_t packet_repository::capacity() const noexcept {
    return capacity_;
}

std::uint64_t packet_repository::evicted_count() const {
    std::lock_guard<std::mutex> lock{mutex_};
    return evicted_count_;
}

void packet_repository::clear() {
    std::lock_guard<std::mutex> lock{mutex_};
    records_.clear();
}

}  // namespace netscope::packet

