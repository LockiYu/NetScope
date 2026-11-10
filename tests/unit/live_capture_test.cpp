#include "netscope/capture/live_capture.h"

#include <pcap/pcap.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <string>

namespace {

using netscope::capture::list_network_interfaces;
using netscope::capture::network_interface;
using netscope::capture::should_select_by_default;
using netscope::capture::validate_bpf_filter;

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

}  // namespace

