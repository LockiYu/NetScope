#include "netscope/extcap/packet_writer.h"

#include "netscope/capture/pcapng.h"

#include <string>
#include <utility>

namespace netscope::extcap {

packet_writer::packet_writer(
    byte_sink sink,
    writer_options options,
    analysis::process_tracker::snapshot_provider provider)
    : sink_{std::move(sink)},
      options_{std::move(options)},
      tracker_{std::move(provider)} {}

bool packet_writer::write_header() {
    const auto section = capture::pcapng_section_header_block();
    if (!sink_(section.data(), section.size())) {
        return false;
    }
    const auto interface_block = capture::pcapng_interface_description_block(
        capture::pcapng_link_type_ethernet,
        options_.snapshot_length,
        options_.interface_name,
        options_.description);
    return sink_(interface_block.data(), interface_block.size());
}

void packet_writer::refresh_processes_if_due() {
    if (!options_.attach_processes) {
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    if (refreshed_at_.has_value() &&
        now - refreshed_at_.value() < options_.process_refresh) {
        return;
    }
    tracker_.refresh();
    refreshed_at_ = now;
}

std::optional<std::string> packet_writer::attribute_comment(
    const capture::captured_packet& packet) {
    refresh_processes_if_due();
    const auto owner = tracker_.lookup(packet);
    if (!owner.has_value()) {
        return std::nullopt;
    }
    if (owner->name.empty()) {
        return "NetScope process: pid " + std::to_string(owner->pid);
    }
    return "NetScope process: " + owner->name + " (pid " +
        std::to_string(owner->pid) + ")";
}

bool packet_writer::write_packet(const capture::captured_packet& packet) {
    const auto comment = attribute_comment(packet);
    const auto block = capture::pcapng_enhanced_packet_block(packet, comment);
    if (!sink_(block.data(), block.size())) {
        return false;
    }
    ++written_;
    return true;
}

std::size_t packet_writer::written_packets() const noexcept {
    return written_;
}

}  // namespace netscope::extcap
