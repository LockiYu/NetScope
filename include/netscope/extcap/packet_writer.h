#pragma once

#include "netscope/analysis/process_tracker.h"
#include "netscope/capture/pcap_file.h"

#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>

namespace netscope::extcap {

struct writer_options {
    std::string interface_name;
    std::string description;
    int snapshot_length{262144};
    bool attach_processes{true};
    std::chrono::seconds process_refresh{5};
};

// Encodes a live capture as pcapng for a Wireshark extcap pipe. Attribute
// comments are added only when a five-tuple can be matched to a local process.
class packet_writer final {
public:
    using byte_sink = std::function<bool(const std::uint8_t* data, std::size_t size)>;

    packet_writer(
        byte_sink sink,
        writer_options options,
        analysis::process_tracker::snapshot_provider provider = {});

    packet_writer(const packet_writer&) = delete;
    packet_writer& operator=(const packet_writer&) = delete;
    packet_writer(packet_writer&&) noexcept = default;
    packet_writer& operator=(packet_writer&&) noexcept = default;

    [[nodiscard]] bool write_header();
    [[nodiscard]] bool write_packet(const capture::captured_packet& packet);
    [[nodiscard]] std::size_t written_packets() const noexcept;

private:
    void refresh_processes_if_due();
    [[nodiscard]] std::optional<std::string> attribute_comment(
        const capture::captured_packet& packet);

    byte_sink sink_;
    writer_options options_;
    analysis::process_tracker tracker_;
    std::optional<std::chrono::steady_clock::time_point> refreshed_at_;
    std::size_t written_{0};
};

}  // namespace netscope::extcap
