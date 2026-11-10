#include "netscope/capture/pcap_file.h"

#include <pcap/pcap.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

namespace netscope::capture {
namespace {

struct pcap_closer {
    void operator()(pcap_t* handle) const noexcept {
        if (handle != nullptr) {
            pcap_close(handle);
        }
    }
};

struct dumper_closer {
    void operator()(pcap_dumper_t* dumper) const noexcept {
        if (dumper != nullptr) {
            pcap_dump_close(dumper);
        }
    }
};

using pcap_handle = std::unique_ptr<pcap_t, pcap_closer>;
using pcap_dumper = std::unique_ptr<pcap_dumper_t, dumper_closer>;

std::string path_string(const std::filesystem::path& path) {
    return path.string();
}

std::chrono::system_clock::time_point to_time_point(const timeval& timestamp) {
    const auto seconds = std::chrono::seconds{
        static_cast<std::chrono::seconds::rep>(timestamp.tv_sec)};
    const auto microseconds = std::chrono::microseconds{
        static_cast<std::chrono::microseconds::rep>(timestamp.tv_usec)};
    return std::chrono::system_clock::time_point{seconds + microseconds};
}

timeval to_timeval(const std::chrono::system_clock::time_point timestamp) {
    const auto total_microseconds =
        std::chrono::duration_cast<std::chrono::microseconds>(
            timestamp.time_since_epoch()).count();
    constexpr auto microseconds_per_second = 1000000LL;
    const auto seconds = total_microseconds / microseconds_per_second;
    auto remaining = total_microseconds % microseconds_per_second;
    if (remaining < 0) {
        remaining += microseconds_per_second;
    }

    timeval result{};
    result.tv_sec = static_cast<decltype(result.tv_sec)>(seconds);
    result.tv_usec = static_cast<decltype(result.tv_usec)>(remaining);
    return result;
}

}  // namespace

pcap_contents read_pcap_file(const std::filesystem::path& path) {
    std::array<char, PCAP_ERRBUF_SIZE> error_buffer{};
    const auto filename = path_string(path);
    pcap_handle handle{pcap_open_offline(filename.c_str(), error_buffer.data())};
    if (!handle) {
        throw pcap_error{
            "failed to open PCAP file '" + filename + "': " + error_buffer.data()};
    }

    pcap_contents result;
    result.link_type = pcap_datalink(handle.get());
    result.snapshot_length = pcap_snapshot(handle.get());

    while (true) {
        pcap_pkthdr* header{nullptr};
        const u_char* data{nullptr};
        const int status = pcap_next_ex(handle.get(), &header, &data);
        if (status == -2) {
            break;
        }
        if (status == -1) {
            throw pcap_error{
                "failed while reading PCAP file '" + filename + "': " +
                pcap_geterr(handle.get())};
        }
        if (status == 0) {
            continue;
        }
        if (header == nullptr || (header->caplen != 0U && data == nullptr)) {
            throw pcap_error{"libpcap returned an invalid packet record"};
        }

        captured_packet packet;
        packet.timestamp = to_time_point(header->ts);
        packet.captured_length = header->caplen;
        packet.original_length = header->len;
        if (header->caplen != 0U) {
            packet.bytes.assign(data, data + header->caplen);
        }
        result.packets.push_back(std::move(packet));
    }

    return result;
}

void write_pcap_file(
    const std::filesystem::path& path,
    const int link_type,
    const int snapshot_length,
    const std::vector<captured_packet>& packets) {
    if (snapshot_length <= 0) {
        throw pcap_error{"snapshot length must be positive"};
    }

    pcap_handle dead_handle{pcap_open_dead(link_type, snapshot_length)};
    if (!dead_handle) {
        throw pcap_error{"failed to create PCAP writer"};
    }

    const auto filename = path_string(path);
    pcap_dumper dumper{pcap_dump_open(dead_handle.get(), filename.c_str())};
    if (!dumper) {
        throw pcap_error{
            "failed to create PCAP file '" + filename + "': " +
            pcap_geterr(dead_handle.get())};
    }

    for (const auto& packet : packets) {
        if (packet.captured_length != packet.bytes.size()) {
            throw pcap_error{"captured length does not match packet byte count"};
        }
        if (packet.original_length < packet.captured_length) {
            throw pcap_error{"original length is smaller than captured length"};
        }

        pcap_pkthdr header{};
        header.ts = to_timeval(packet.timestamp);
        header.caplen = packet.captured_length;
        header.len = packet.original_length;
        pcap_dump(
            reinterpret_cast<u_char*>(dumper.get()),
            &header,
            packet.bytes.empty() ? nullptr : packet.bytes.data());
    }

    if (pcap_dump_flush(dumper.get()) != 0) {
        throw pcap_error{
            "failed to flush PCAP file '" + filename + "': " +
            pcap_geterr(dead_handle.get())};
    }
}

}  // namespace netscope::capture

