#pragma once

#include "netscope/capture/pcap_file.h"
#include "netscope/packet/packet_repository.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace netscope::analysis {

struct process_socket {
    std::string transport;
    std::string local_address;
    std::uint16_t local_port{0U};
    std::string remote_address;
    std::uint16_t remote_port{0U};
    std::string process_name;
    std::int32_t pid{0};
};

class process_tracker final {
public:
    using snapshot_provider = std::function<std::vector<process_socket>()>;

    process_tracker();
    explicit process_tracker(snapshot_provider provider);
    ~process_tracker();

    process_tracker(const process_tracker&) = delete;
    process_tracker& operator=(const process_tracker&) = delete;
    process_tracker(process_tracker&&) noexcept;
    process_tracker& operator=(process_tracker&&) noexcept;

    void refresh();
    void ingest(std::vector<process_socket> sockets);

    [[nodiscard]] std::optional<packet::process_owner> lookup(
        const capture::captured_packet& packet) const;

    [[nodiscard]] std::optional<packet::process_owner> lookup(
        std::string_view transport,
        std::string_view source,
        std::uint16_t source_port,
        std::string_view destination,
        std::uint16_t destination_port) const;

    [[nodiscard]] std::vector<process_socket> sockets() const;
    [[nodiscard]] std::size_t socket_count() const;
    void clear();

private:
    class implementation;
    std::unique_ptr<implementation> implementation_;
};

[[nodiscard]] std::vector<process_socket> list_local_sockets();

}  // namespace netscope::analysis
