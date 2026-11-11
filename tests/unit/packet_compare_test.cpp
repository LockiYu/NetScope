#include "netscope/analysis/packet_compare.h"

#include <gtest/gtest.h>

#include <algorithm>

namespace {

TEST(packet_compare_test, reports_changed_and_missing_protocol_fields_by_path) {
    const netscope::protocol::protocol_node left{
        "Frame", {0U, 10U}, {},
        {{"IPv4", {0U, 10U},
          {{"ttl", "64", "64", {1U, 1U}},
           {"source", "10.0.0.1", "10.0.0.1", {2U, 4U}}},
          {}, {}}}, {}};
    const netscope::protocol::protocol_node right{
        "Frame", {0U, 10U}, {},
        {{"IPv4", {0U, 10U},
          {{"ttl", "63", "63", {1U, 1U}},
           {"destination", "10.0.0.2", "10.0.0.2", {6U, 4U}}},
          {}, {}}}, {}};

    const auto differences = netscope::analysis::compare_protocol_trees(left, right);

    const auto ttl = std::find_if(differences.begin(), differences.end(), [](const auto& item) {
        return item.path == "Frame/IPv4/ttl";
    });
    ASSERT_NE(ttl, differences.end());
    EXPECT_EQ(ttl->left_value, "64");
    EXPECT_EQ(ttl->right_value, "63");
    EXPECT_TRUE(std::any_of(differences.begin(), differences.end(), [](const auto& item) {
        return item.path == "Frame/IPv4/source" && item.right_value.empty();
    }));
    EXPECT_TRUE(std::any_of(differences.begin(), differences.end(), [](const auto& item) {
        return item.path == "Frame/IPv4/destination" && item.left_value.empty();
    }));
}

TEST(packet_compare_test, omits_equal_fields) {
    const netscope::protocol::protocol_node packet{
        "Frame", {0U, 1U}, {{"length", "1", "1 byte", {0U, 1U}}}, {}, {}};
    EXPECT_TRUE(netscope::analysis::compare_protocol_trees(packet, packet).empty());
}

}  // namespace
