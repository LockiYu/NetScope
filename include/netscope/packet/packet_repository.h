#pragma once

#include "netscope/capture/packet_merger.h"
#include "netscope/protocol/protocol_model.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace netscope::packet {

struct packet_record {
    std::uint64_t number{0};
    capture::merged_packet capture;
    protocol::protocol_node analysis;
    std::string source;
    std::string destination;
    std::string protocol;
    std::string information;
};

class packet_repository final {
public:
    explicit packet_repository(std::size_t capacity = 100000);

    [[nodiscard]] std::shared_ptr<const packet_record> append(
        capture::merged_packet packet);
    [[nodiscard]] std::shared_ptr<const packet_record> at(std::size_t index) const;
    [[nodiscard]] std::vector<std::shared_ptr<const packet_record>> snapshot() const;
    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] std::size_t capacity() const noexcept;
    [[nodiscard]] std::uint64_t evicted_count() const;
    void clear();

private:
    std::size_t capacity_;
    mutable std::mutex mutex_;
    std::deque<std::shared_ptr<const packet_record>> records_;
    std::uint64_t next_number_{1};
    std::uint64_t evicted_count_{0};
};

}  // namespace netscope::packet

