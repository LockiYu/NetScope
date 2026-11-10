#include "netscope/ui/main_window.h"

#include "netscope/packet/packet_repository.h"

#include <QApplication>
#include <QDockWidget>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QTableView>
#include <QTreeWidget>

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>

namespace {

std::shared_ptr<const netscope::packet::packet_record> make_record() {
    std::vector<std::uint8_t> bytes{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, 0, 0x28, 0, 1, 0x40, 0, 64, 6, 0, 0,
        192, 168, 1, 10, 8, 8, 8, 8,
        0x04, 0xd2, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0,
        0x50, 0x02, 0x40, 0, 0, 0, 0, 0,
    };
    netscope::packet::packet_repository repository{1};
    return repository.append(netscope::capture::merged_packet{
        netscope::capture::captured_packet{
            std::chrono::system_clock::time_point{std::chrono::microseconds{1000002}},
            static_cast<std::uint32_t>(bytes.size()),
            static_cast<std::uint32_t>(bytes.size()),
            std::move(bytes),
        },
        {"en0"},
    });
}

TEST(main_window_test, provides_a_ready_application_shell) {
    netscope::ui::main_window window;

    EXPECT_EQ(window.windowTitle(), QStringLiteral("NetScope"));
    EXPECT_NE(window.centralWidget(), nullptr);
    EXPECT_GE(window.minimumWidth(), 960);
    EXPECT_GE(window.minimumHeight(), 640);
}

TEST(main_window_test, provides_packet_protocol_and_hex_workspaces) {
    netscope::ui::main_window window;

    const auto* packet_table = window.findChild<QTableView*>(QStringLiteral("packetTable"));
    const auto* protocol_tree = window.findChild<QTreeWidget*>(QStringLiteral("protocolTree"));
    const auto* hex_view = window.findChild<QPlainTextEdit*>(QStringLiteral("hexView"));

    ASSERT_NE(packet_table, nullptr);
    ASSERT_NE(protocol_tree, nullptr);
    ASSERT_NE(hex_view, nullptr);
    EXPECT_TRUE(packet_table->isSortingEnabled());
    EXPECT_EQ(protocol_tree->columnCount(), 2);
    EXPECT_TRUE(hex_view->isReadOnly());
}

TEST(main_window_test, provides_capture_controls_and_multi_interface_selection) {
    netscope::ui::main_window window;

    EXPECT_NE(window.findChild<QListWidget*>(QStringLiteral("interfaceList")), nullptr);
    EXPECT_NE(window.findChild<QLineEdit*>(QStringLiteral("captureFilterEdit")), nullptr);
    EXPECT_NE(window.findChild<QDockWidget*>(QStringLiteral("captureDock")), nullptr);
    EXPECT_NE(window.findChild<QObject*>(QStringLiteral("startCaptureAction")), nullptr);
    EXPECT_NE(window.findChild<QObject*>(QStringLiteral("pauseCaptureAction")), nullptr);
    EXPECT_NE(window.findChild<QObject*>(QStringLiteral("stopCaptureAction")), nullptr);
}

TEST(main_window_test, updates_protocol_and_hex_views_for_selected_packet) {
    netscope::ui::main_window window;
    auto* const packet_table = window.findChild<QTableView*>(QStringLiteral("packetTable"));
    auto* const protocol_tree = window.findChild<QTreeWidget*>(QStringLiteral("protocolTree"));
    auto* const hex_view = window.findChild<QPlainTextEdit*>(QStringLiteral("hexView"));

    window.append_packet(make_record());
    packet_table->selectRow(0);
    QApplication::processEvents();

    ASSERT_EQ(packet_table->model()->rowCount(), 1);
    EXPECT_GT(protocol_tree->topLevelItemCount(), 0);
    EXPECT_TRUE(hex_view->toPlainText().contains(QStringLiteral("00 01 02 03")));
}

}  // namespace

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", QByteArrayLiteral("offscreen"));
    QApplication application{argc, argv};
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

