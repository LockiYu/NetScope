#include "netscope/capture/live_capture.h"

#include <pcap/pcap.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <optional>
#include <queue>
#include <string>

namespace {

using netscope::capture::list_network_interfaces;
using netscope::capture::network_interface;
using netscope::capture::capture_backend;
using netscope::capture::capture_options;
using netscope::capture::capture_session;
using netscope::capture::capture_state;
using netscope::capture::capture_statistics;
using netscope::capture::captured_packet;
using netscope::capture::should_select_by_default;
using netscope::capture::validate_bpf_filter;
using netscope::capture::validate_capture_options;

struct fake_backend_state {
    int next_calls{0};
    int break_calls{0};
};

class fake_backend final : public capture_backend {
public:
    explicit fake_backend(std::shared_ptr<fake_backend_state> state)
        : state_{std::move(state)} {
        packets_.push(captured_packet{
            std::chrono::system_clock::time_point{}, 1U, 1U, {0xaa}});
    }

    std::optional<captured_packet> next_packet() override {
        ++state_->next_calls;
        if (packets_.empty()) {
            return std::nullopt;
        }
        auto packet = std::move(packets_.front());
        packets_.pop();
        return packet;
    }

    void break_capture() noexcept override {
        ++state_->break_calls;
    }

    capture_statistics statistics() const override {
        return capture_statistics{1U, 2U, 3U};
    }

private:
    std::shared_ptr<fake_backend_state> state_;
    std::queue<captured_packet> packets_;
};

TEST(live_capture_test, enumerates_the_macos_loopback_interface) {
    const auto interfaces = list_network_interfaces();

    ASSERT_FALSE(interfaces.empty());
    EXPECT_NE(
        std::find_if(interfaces.begin(), interfaces.end(), [](const auto& interface) {
            return interface.name == "lo0" && interface.is_loopback;
        }),
        interfaces.end());
}

TEST(live_capture_test, excludes_tunnels_loopback_and_inactive_interfaces_by_default) {
    network_interface physical;
    physical.name = "en0";
    physical.is_up = true;
    physical.is_running = true;

    auto tunnel = physical;
    tunnel.name = "utun3";
    tunnel.is_tunnel = true;

    auto loopback = physical;
    loopback.name = "lo0";
    loopback.is_loopback = true;

    auto inactive = physical;
    inactive.is_running = false;

    EXPECT_TRUE(should_select_by_default(physical));
    EXPECT_FALSE(should_select_by_default(tunnel));
    EXPECT_FALSE(should_select_by_default(loopback));
    EXPECT_FALSE(should_select_by_default(inactive));
}

TEST(live_capture_test, validates_bpf_without_starting_capture) {
    EXPECT_FALSE(validate_bpf_filter("tcp and port 443", DLT_EN10MB, 65535).has_value());

    const auto error = validate_bpf_filter("tcp and and", DLT_EN10MB, 65535);
    ASSERT_TRUE(error.has_value());
    EXPECT_FALSE(error->empty());
}

TEST(live_capture_test, controls_capture_lifecycle_without_consuming_while_paused) {
    const auto backend_state = std::make_shared<fake_backend_state>();
    capture_session session{
        std::make_unique<fake_backend>(backend_state), "en0"};

    EXPECT_EQ(session.state(), capture_state::active);
    session.pause();
    EXPECT_EQ(session.state(), capture_state::paused);
    EXPECT_FALSE(session.next_packet().has_value());
    EXPECT_EQ(backend_state->next_calls, 0);

    session.resume();
    const auto packet = session.next_packet();
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(packet->bytes, std::vector<std::uint8_t>{0xaa});
    EXPECT_EQ(session.statistics().dropped, 2U);

    session.stop();
    EXPECT_EQ(session.state(), capture_state::stopped);
    EXPECT_EQ(backend_state->break_calls, 1);
    EXPECT_FALSE(session.next_packet().has_value());
}

TEST(live_capture_test, rejects_invalid_capture_options) {
    capture_options options;
    options.snapshot_length = 0;
    EXPECT_TRUE(validate_capture_options(options).has_value());

    options.snapshot_length = 65535;
    options.read_timeout = std::chrono::milliseconds{-1};
    EXPECT_TRUE(validate_capture_options(options).has_value());

    options.read_timeout = std::chrono::milliseconds{100};
    options.buffer_size = 0;
    EXPECT_TRUE(validate_capture_options(options).has_value());
}

}  // namespace

