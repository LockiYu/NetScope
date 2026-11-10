#include "netscope/ui/main_window.h"

#include <QApplication>
#include <QDockWidget>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QTableView>
#include <QTreeWidget>

#include <gtest/gtest.h>

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

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", QByteArrayLiteral("offscreen"));
    QApplication application{argc, argv};
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

