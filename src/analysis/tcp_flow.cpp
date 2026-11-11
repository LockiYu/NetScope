#include "netscope/analysis/tcp_flow.h"

#include "netscope/packet/packet_repository.h"

#include <algorithm>
#include <array>
#include <map>
#include <mutex>
#include <stdexcept>
#include <tuple>
#include <utility>

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

std::uint32_t unsigned_value(const protocol::protocol_field* const value) {
    if (value == nullptr || value->raw_value.empty()) {
        throw std::invalid_argument{"required TCP field is missing"};
    }
    return static_cast<std::uint32_t>(std::stoul(value->raw_value, nullptr, 0));
}

bool endpoint_less(const tcp_endpoint& left, const tcp_endpoint& right) {
    return std::tie(left.address, left.port) < std::tie(right.address, right.port);
}

struct flow_key {
    tcp_endpoint first;
    tcp_endpoint second;

    bool operator<(const flow_key& other) const {
        return std::tie(first.address, first.port, second.address, second.port) <
               std::tie(other.first.address, other.first.port,
                        other.second.address, other.second.port);
    }
};

flow_key normalized_key(tcp_endpoint source, tcp_endpoint destination) {
    if (endpoint_less(destination, source)) {
        std::swap(source, destination);
    }
    return flow_key{std::move(source), std::move(destination)};
}

bool same_endpoint(const tcp_endpoint& left, const tcp_endpoint& right) {
    return left.address == right.address && left.port == right.port;
}

struct direction_state {
    std::optional<std::uint32_t> next_sequence;
    std::map<std::uint32_t, std::vector<std::uint8_t>> pending;
    std::vector<std::uint8_t> reassembled;
    std::optional<std::uint32_t> last_acknowledgement;
};

struct flow_state_data {
    tcp_flow_snapshot snapshot;
    std::array<direction_state, 2> directions;
    std::array<bool, 2> fin_seen{false, false};
    std::optional<std::chrono::system_clock::time_point> syn_time;
    std::optional<tcp_endpoint> syn_source;
};

void append_contiguous(direction_state& direction) {
    while (direction.next_sequence.has_value()) {
        const auto found = direction.pending.find(direction.next_sequence.value());
        if (found == direction.pending.end()) {
            break;
        }
        direction.reassembled.insert(
            direction.reassembled.end(), found->second.begin(), found->second.end());
        direction.next_sequence = static_cast<std::uint32_t>(
            direction.next_sequence.value() + found->second.size());
        direction.pending.erase(found);
    }
}

void ingest_payload(
    direction_state& direction,
    std::uint32_t sequence,
    std::vector<std::uint8_t> payload,
    tcp_flow_snapshot& snapshot) {
    if (payload.empty()) {
        return;
    }
    if (!direction.next_sequence.has_value()) {
        direction.next_sequence = sequence;
    }
    if (sequence < direction.next_sequence.value()) {
        ++snapshot.retransmissions;
        const auto overlap = static_cast<std::size_t>(
            direction.next_sequence.value() - sequence);
        if (overlap >= payload.size()) {
            return;
        }
        payload.erase(payload.begin(), payload.begin() +
            static_cast<std::vector<std::uint8_t>::difference_type>(overlap));
        sequence = direction.next_sequence.value();
    }
    if (sequence > direction.next_sequence.value()) {
        ++snapshot.out_of_order_segments;
        if (direction.pending.find(sequence) != direction.pending.end()) {
            ++snapshot.retransmissions;
        } else {
            direction.pending.emplace(sequence, std::move(payload));
        }
        return;
    }
    direction.reassembled.insert(
        direction.reassembled.end(), payload.begin(), payload.end());
    direction.next_sequence = static_cast<std::uint32_t>(sequence + payload.size());
    append_contiguous(direction);
}

}  // namespace

class tcp_flow_tracker::implementation final {
public:
    mutable std::mutex mutex;
    std::map<flow_key, flow_state_data> flows;
    std::uint64_t next_id{1U};
};

tcp_flow_tracker::tcp_flow_tracker()
    : implementation_{std::make_unique<implementation>()} {}

tcp_flow_tracker::~tcp_flow_tracker() = default;
tcp_flow_tracker::tcp_flow_tracker(tcp_flow_tracker&&) noexcept = default;
tcp_flow_tracker& tcp_flow_tracker::operator=(tcp_flow_tracker&&) noexcept = default;

std::optional<std::uint64_t> tcp_flow_tracker::ingest(
    std::shared_ptr<const packet::packet_record> packet) {
    if (!packet) {
        return std::nullopt;
    }
    const auto* tcp = find_node(packet->analysis, "Transmission Control Protocol");
    if (tcp == nullptr || packet->source.empty() || packet->destination.empty()) {
        return std::nullopt;
    }

    try {
        const auto source_port = static_cast<std::uint16_t>(
            unsigned_value(find_field(*tcp, "source_port")));
        const auto destination_port = static_cast<std::uint16_t>(
            unsigned_value(find_field(*tcp, "destination_port")));
        const auto sequence = unsigned_value(find_field(*tcp, "sequence_number"));
        const auto acknowledgement = unsigned_value(
            find_field(*tcp, "acknowledgement_number"));
        const auto flags = static_cast<std::uint16_t>(
            unsigned_value(find_field(*tcp, "flags")));
        tcp_endpoint source{packet->source, source_port};
        tcp_endpoint destination{packet->destination, destination_port};
        const auto key = normalized_key(source, destination);

        std::lock_guard lock{implementation_->mutex};
        auto found = implementation_->flows.find(key);
        if (found == implementation_->flows.end()) {
            flow_state_data created;
            created.snapshot.id = implementation_->next_id++;
            const bool initiating_syn = (flags & 0x002U) != 0U && (flags & 0x010U) == 0U;
            if (initiating_syn || endpoint_less(source, destination)) {
                created.snapshot.client = source;
                created.snapshot.server = destination;
            } else {
                created.snapshot.client = destination;
                created.snapshot.server = source;
            }
            found = implementation_->flows.emplace(key, std::move(created)).first;
        }
        auto& flow = found->second;
        const std::size_t direction_index =
            same_endpoint(source, flow.snapshot.client) ? 0U : 1U;
        auto& direction = flow.directions[direction_index];

        ++flow.snapshot.packet_count;
        flow.snapshot.byte_count += packet->capture.packet.original_length;
        flow.snapshot.packet_numbers.push_back(packet->number);

        const bool syn = (flags & 0x002U) != 0U;
        const bool ack = (flags & 0x010U) != 0U;
        const bool fin = (flags & 0x001U) != 0U;
        const bool reset = (flags & 0x004U) != 0U;
        if (syn && !ack) {
            flow.syn_time = packet->capture.packet.timestamp;
            flow.syn_source = source;
            flow.snapshot.state = tcp_flow_state::opening;
        } else if (syn && ack && flow.syn_time.has_value() &&
                   flow.syn_source.has_value() &&
                   !same_endpoint(source, flow.syn_source.value())) {
            flow.snapshot.round_trip_time =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    packet->capture.packet.timestamp - flow.syn_time.value());
        } else if (ack && flow.syn_time.has_value() &&
                   flow.snapshot.round_trip_time.has_value()) {
            flow.snapshot.state = tcp_flow_state::established;
        }
        if (reset) {
            flow.snapshot.state = tcp_flow_state::reset;
        }
        if (fin) {
            flow.fin_seen[direction_index] = true;
            flow.snapshot.state = flow.fin_seen[0] && flow.fin_seen[1]
                ? tcp_flow_state::closed
                : tcp_flow_state::half_closed;
        }

        std::vector<std::uint8_t> payload;
        if (const auto* payload_field = find_field(*tcp, "payload");
            payload_field != nullptr &&
            payload_field->bytes.offset <= packet->capture.packet.bytes.size() &&
            payload_field->bytes.length <=
                packet->capture.packet.bytes.size() - payload_field->bytes.offset) {
            const auto begin = packet->capture.packet.bytes.begin() +
                static_cast<std::vector<std::uint8_t>::difference_type>(
                    payload_field->bytes.offset);
            payload.assign(
                begin,
                begin + static_cast<std::vector<std::uint8_t>::difference_type>(
                    payload_field->bytes.length));
        }
        if (ack && payload.empty() && direction.last_acknowledgement.has_value() &&
            direction.last_acknowledgement.value() == acknowledgement) {
            ++flow.snapshot.duplicate_acknowledgements;
        }
        if (ack) {
            direction.last_acknowledgement = acknowledgement;
        }
        const auto payload_sequence = static_cast<std::uint32_t>(sequence + (syn ? 1U : 0U));
        ingest_payload(direction, payload_sequence, std::move(payload), flow.snapshot);
        flow.snapshot.client_to_server_data = flow.directions[0].reassembled;
        flow.snapshot.server_to_client_data = flow.directions[1].reassembled;
        return flow.snapshot.id;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::vector<tcp_flow_snapshot> tcp_flow_tracker::snapshot() const {
    std::lock_guard lock{implementation_->mutex};
    std::vector<tcp_flow_snapshot> result;
    result.reserve(implementation_->flows.size());
    for (const auto& [key, flow] : implementation_->flows) {
        static_cast<void>(key);
        result.push_back(flow.snapshot);
    }
    return result;
}

void tcp_flow_tracker::clear() {
    std::lock_guard lock{implementation_->mutex};
    implementation_->flows.clear();
    implementation_->next_id = 1U;
}

}  // namespace netscope::analysis
