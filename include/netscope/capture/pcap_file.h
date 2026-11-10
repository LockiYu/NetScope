#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <vector>

namespace netscope::capture {

class pcap_error final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct captured_packet {
    std::chrono::system_clock::time_point timestamp;
    std::uint32_t captured_length{0};
    std::uint32_t original_length{0};
    std::vector<std::uint8_t> bytes;
};

struct pcap_contents {
    int link_type{0};
    int snapshot_length{0};
    std::vector<captured_packet> packets;
};

[[nodiscard]] pcap_contents read_pcap_file(const std::filesystem::path& path);

void write_pcap_file(
    const std::filesystem::path& path,
    int link_type,
    int snapshot_length,
    const std::vector<captured_packet>& packets);

}  // namespace netscope::capture

