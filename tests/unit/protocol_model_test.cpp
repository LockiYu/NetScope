#include "netscope/protocol/protocol_model.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <gtest/gtest.h>

namespace {

using netscope::protocol::byte_range;
using netscope::protocol::protocol_field;
using netscope::protocol::protocol_node;
using netscope::protocol::to_json;
using netscope::protocol::validation_status;

TEST(protocol_model_test, byte_ranges_use_half_open_bounds) {
    const byte_range range{10, 4};

    EXPECT_TRUE(range.contains(10));
    EXPECT_TRUE(range.contains(13));
    EXPECT_FALSE(range.contains(14));
    EXPECT_FALSE(range.contains(9));
}

TEST(protocol_model_test, exports_nested_fields_and_warnings_as_json) {
    protocol_node root{
        "Frame",
        byte_range{0, 64},
        {protocol_field{
            "captured_length",
            "64",
            "64 bytes",
            byte_range{0, 0},
            std::nullopt,
            std::nullopt,
            validation_status::valid,
            {},
        }},
        {protocol_node{
            "Ethernet II",
            byte_range{0, 14},
            {},
            {},
            {"example warning"},
        }},
        {},
    };

    const auto document = QJsonDocument::fromJson(
        QByteArray::fromStdString(to_json(root)));

    ASSERT_FALSE(document.isNull());
    const auto object = document.object();
    EXPECT_EQ(object.value(QStringLiteral("name")).toString(),
              QStringLiteral("Frame"));
    ASSERT_EQ(object.value(QStringLiteral("children")).toArray().size(), 1);
    EXPECT_EQ(object.value(QStringLiteral("fields")).toArray().size(), 1);
}

}  // namespace

