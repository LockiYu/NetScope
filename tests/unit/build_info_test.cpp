#include "netscope/build_info.h"

#include <gtest/gtest.h>

TEST(build_info_test, reports_linked_qt_and_pcap_versions) {
    const auto info = netscope::current_build_info();

    EXPECT_FALSE(info.qt_version.empty());
    EXPECT_FALSE(info.pcap_version.empty());
}

