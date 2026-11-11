#include "netscope/analysis/ip_reassembly.h"

#include "netscope/packet/packet_repository.h"

#include <algorithm>
#include <tuple>
#include <utility>

namespace netscope::analysis {
namespace {

struct parsed_fragment {
    std::uint8_t version{0};
    std::string source;
    std::string destination;
    std::uint32_t identification{0};
    std::uint8_t next_header{0};
    std::size_t offset{0};
    bool more_fragments{false};
    std::vector<std::uint8_t> payload;
};

std::uint16_t read_u16(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(bytes[offset]) << 8U |
        static_cast<std::uint16_t>(bytes[offset + 1U]));
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint32_t>(
        static_cast<std::uint32_t>(bytes[offset]) << 24U |
        static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U |
        static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U |
        static_cast<std::uint32_t>(bytes[offset + 3U]));
}

std::optional<std::pair<std::uint16_t, std::size_t>> ethernet_payload(
    const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() < 14U) {
        return std::nullopt;
    }
    auto type = read_u16(bytes, 12U);
    std::size_t offset{14U};
    while (type == 0x8100U || type == 0x88a8U) {
        if (offset + 4U > bytes.size()) {
            return std::nullopt;
        }
        type = read_u16(bytes, offset + 2U);
        offset += 4U;
    }
    return std::pair{type, offset};
}

bool is_extension(const std::uint8_t header) noexcept {
    return header == 0U || header == 43U || header == 44U ||
           header == 51U || header == 60U;
}

std::optional<parsed_fragment> parse_fragment(const packet::packet_record& record) {
    const auto& bytes = record.capture.packet.bytes;
    const auto link = ethernet_payload(bytes);
    if (!link.has_value()) {
        return std::nullopt;
    }
    const auto [ether_type, network_offset] = link.value();
    if (ether_type == 0x0800U) {
        if (network_offset + 20U > bytes.size() ||
            (bytes[network_offset] >> 4U) != 4U) {
            return std::nullopt;
        }
        const auto header_length =
            static_cast<std::size_t>(bytes[network_offset] & 0x0fU) * 4U;
        if (header_length < 20U || network_offset + header_length > bytes.size()) {
            return std::nullopt;
        }
        const auto flags_offset = read_u16(bytes, network_offset + 6U);
        const bool more = (flags_offset & 0x2000U) != 0U;
        const auto offset = static_cast<std::size_t>(flags_offset & 0x1fffU) * 8U;
        if (!more && offset == 0U) {
            return std::nullopt;
        }
        const auto declared_end = network_offset + static_cast<std::size_t>(
            read_u16(bytes, network_offset + 2U));
        const auto payload_begin = network_offset + header_length;
        const auto payload_end = std::min(bytes.size(), declared_end);
        if (payload_end < payload_begin) {
            return std::nullopt;
        }
        return parsed_fragment{
            4U,
            record.source,
            record.destination,
            read_u16(bytes, network_offset + 4U),
            bytes[network_offset + 9U],
            offset,
            more,
            {bytes.begin() + static_cast<std::ptrdiff_t>(payload_begin),
             bytes.begin() + static_cast<std::ptrdiff_t>(payload_end)},
        };
    }
    if (ether_type != 0x86ddU || network_offset + 40U > bytes.size() ||
        (bytes[network_offset] >> 4U) != 6U) {
        return std::nullopt;
    }

    const auto declared_end = std::min(
        bytes.size(),
        network_offset + 40U +
            static_cast<std::size_t>(read_u16(bytes, network_offset + 4U)));
    auto next = bytes[network_offset + 6U];
    auto cursor = network_offset + 40U;
    std::size_t extension_count{0U};
    while (is_extension(next) && extension_count < 16U) {
        if (cursor + 2U > declared_end) {
            return std::nullopt;
        }
        if (next == 44U) {
            if (cursor + 8U > declared_end) {
                return std::nullopt;
            }
            const auto fragment_bits = read_u16(bytes, cursor + 2U);
            const auto offset = static_cast<std::size_t>(fragment_bits >> 3U) * 8U;
            const bool more = (fragment_bits & 1U) != 0U;
            if (!more && offset == 0U) {
                return std::nullopt;
            }
            return parsed_fragment{
                6U,
                record.source,
                record.destination,
                read_u32(bytes, cursor + 4U),
                bytes[cursor],
                offset,
                more,
                {bytes.begin() + static_cast<std::ptrdiff_t>(cursor + 8U),
                 bytes.begin() + static_cast<std::ptrdiff_t>(declared_end)},
            };
        }
        const auto following = bytes[cursor];
        const auto length = next == 51U
            ? (static_cast<std::size_t>(bytes[cursor + 1U]) + 2U) * 4U
            : (static_cast<std::size_t>(bytes[cursor + 1U]) + 1U) * 8U;
        if (length < 8U || cursor + length > declared_end) {
            return std::nullopt;
        }
        next = following;
        cursor += length;
        ++extension_count;
    }
    return std::nullopt;
}

}  // namespace

bool ip_reassembler::fragment_key::operator<(
    const fragment_key& other) const noexcept {
    return std::tie(version, source, destination, identification, next_header) <
           std::tie(
               other.version,
               other.source,
               other.destination,
               other.identification,
               other.next_header);
}

std::optional<reassembled_datagram> ip_reassembler::ingest(
    std::shared_ptr<const packet::packet_record> packet) {
    if (!packet) {
        return std::nullopt;
    }
    auto fragment = parse_fragment(*packet);
    if (!fragment.has_value()) {
        return std::nullopt;
    }
    fragment_key key{
        fragment->version,
        fragment->source,
        fragment->destination,
        fragment->identification,
        fragment->next_header,
    };
    auto& partial = pending_[key];
    const auto end = fragment->offset + fragment->payload.size();
    if (end > 65535U) {
        pending_.erase(key);
        return std::nullopt;
    }
    if (partial.bytes.size() < end) {
        partial.bytes.resize(end);
        partial.present.resize(end, false);
    }
    for (std::size_t index = 0U; index < fragment->payload.size(); ++index) {
        const auto position = fragment->offset + index;
        if (partial.present[position]) {
            ++partial.overlapping_bytes;
        } else {
            partial.bytes[position] = fragment->payload[index];
            partial.present[position] = true;
        }
    }
    ++partial.fragment_count;
    partial.packet_numbers.push_back(packet->number);
    if (!fragment->more_fragments) {
        partial.total_size = end;
    }
    if (!partial.total_size.has_value() || partial.present.size() < partial.total_size.value() ||
        !std::all_of(
            partial.present.begin(),
            partial.present.begin() + static_cast<std::ptrdiff_t>(partial.total_size.value()),
            [](const bool value) { return value; })) {
        if (pending_.size() > 1024U) {
            pending_.erase(pending_.begin());
        }
        return std::nullopt;
    }

    reassembled_datagram result{
        key.version,
        key.source,
        key.destination,
        key.identification,
        key.next_header,
        {partial.bytes.begin(),
         partial.bytes.begin() + static_cast<std::ptrdiff_t>(partial.total_size.value())},
        partial.fragment_count,
        partial.overlapping_bytes,
        std::move(partial.packet_numbers),
    };
    pending_.erase(key);
    return result;
}

std::size_t ip_reassembler::pending_count() const noexcept {
    return pending_.size();
}

void ip_reassembler::clear() noexcept {
    pending_.clear();
}

}  // namespace netscope::analysis
