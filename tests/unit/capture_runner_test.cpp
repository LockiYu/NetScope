#include "netscope/capture/capture_runner.h"

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace {

using namespace std::chrono_literals;
using netscope::capture::capture_backend;
using netscope::capture::capture_options;
using netscope::capture::capture_runner;
using netscope::capture::capture_session;
using netscope::capture::capture_statistics;
using netscope::capture::captured_packet;
using netscope::capture::interface_packet;

class one_packet_backend final : public capture_backend {
public:
    explicit one_packet_backend(const std::uint8_t value) : value_{value} {}

    std::optional<captured_packet> next_packet() override {
        if (delivered_) {
            return std::nullopt;
        }
        delivered_ = true;
        return captured_packet{
            std::chrono::system_clock::now(), 1U, 1U, {value_}};
    }

    void break_capture() noexcept override {}
    capture_statistics statistics() const override { return {}; }

private:
    std::uint8_t value_;
    bool delivered_{false};
};

TEST(capture_runner_test, streams_packets_from_multiple_interfaces_and_stops_cleanly) {
    capture_runner runner{[](const std::string& name, const capture_options&) {
        const auto value = name == "en0" ? std::uint8_t{1U} : std::uint8_t{2U};
        return capture_session{std::make_unique<one_packet_backend>(value), name};
    }};
    std::mutex mutex;
    std::condition_variable ready;
    std::vector<interface_packet> received;

    runner.start({"en0", "en1"}, {}, [&](interface_packet packet) {
        {
            const std::lock_guard lock{mutex};
            received.push_back(std::move(packet));
        }
        ready.notify_one();
    });

    {
        std::unique_lock lock{mutex};
        ASSERT_TRUE(ready.wait_for(lock, 1s, [&] { return received.size() == 2U; }));
    }
    runner.stop();

    EXPECT_FALSE(runner.running());
    ASSERT_EQ(received.size(), 2U);
    EXPECT_EQ(received[0].packet.bytes.size(), 1U);
    EXPECT_NE(received[0].interface_name, received[1].interface_name);
}

TEST(capture_runner_test, rejects_empty_or_duplicate_start_requests) {
    capture_runner runner{[](const std::string& name, const capture_options&) {
        return capture_session{std::make_unique<one_packet_backend>(1U), name};
    }};

    EXPECT_THROW(runner.start({}, {}, [](interface_packet) {}), std::invalid_argument);
    runner.start({"en0"}, {}, [](interface_packet) {});
    EXPECT_THROW(
        runner.start({"en1"}, {}, [](interface_packet) {}),
        std::logic_error);
    runner.stop();
}

}  // namespace
