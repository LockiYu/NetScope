#include "netscope/ui/main_window.h"

#include "netscope/packet/packet_repository.h"

#include <QApplication>
#include <QComboBox>
#include <QDockWidget>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTableView>
#include <QTreeWidget>

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>

namespace {

QTreeWidgetItem* find_item(QTreeWidgetItem* const root, const QString& name) {
    if (root->text(0) == name) {
        return root;
    }
    for (int index = 0; index < root->childCount(); ++index) {
        if (auto* const match = find_item(root->child(index), name); match != nullptr) {
            return match;
        }
    }
    return nullptr;
}

QTreeWidgetItem* find_item(QTreeWidget* const tree, const QString& name) {
    for (int index = 0; index < tree->topLevelItemCount(); ++index) {
        if (auto* const match = find_item(tree->topLevelItem(index), name);
            match != nullptr) {
            return match;
        }
    }
    return nullptr;
}

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

TEST(main_window_test, synchronizes_protocol_fields_and_hex_byte_selection) {
    netscope::ui::main_window window;
    auto* const packet_table = window.findChild<QTableView*>(QStringLiteral("packetTable"));
    auto* const protocol_tree = window.findChild<QTreeWidget*>(QStringLiteral("protocolTree"));
    auto* const hex_view = window.findChild<QPlainTextEdit*>(QStringLiteral("hexView"));

    window.append_packet(make_record());
    packet_table->selectRow(0);
    QApplication::processEvents();

    auto* const source_address =
        find_item(protocol_tree, QStringLiteral("source_address"));
    ASSERT_NE(source_address, nullptr);
    protocol_tree->setCurrentItem(source_address);
    QApplication::processEvents();
    EXPECT_TRUE(
        hex_view->textCursor().selectedText().contains(QStringLiteral("c0 a8 01 0a")));

    QTextCursor cursor = hex_view->textCursor();
    cursor.clearSelection();
    const auto source_text = hex_view->toPlainText().indexOf(QStringLiteral("c0 a8 01 0a"));
    ASSERT_GE(source_text, 0);
    cursor.setPosition(static_cast<int>(source_text + 1));
    hex_view->setTextCursor(cursor);
    QApplication::processEvents();

    ASSERT_NE(protocol_tree->currentItem(), nullptr);
    EXPECT_EQ(protocol_tree->currentItem()->text(0), QStringLiteral("source_address"));
}

TEST(main_window_test, searches_jumps_and_interprets_packet_bytes) {
    netscope::ui::main_window window;
    auto* const packet_table = window.findChild<QTableView*>(QStringLiteral("packetTable"));
    auto* const hex_view = window.findChild<QPlainTextEdit*>(QStringLiteral("hexView"));
    auto* const search = window.findChild<QLineEdit*>(QStringLiteral("hexSearchEdit"));
    auto* const find_next = window.findChild<QPushButton*>(QStringLiteral("hexFindNextButton"));
    auto* const offset = window.findChild<QSpinBox*>(QStringLiteral("hexOffsetSpin"));
    auto* const go_to = window.findChild<QPushButton*>(QStringLiteral("hexGoButton"));
    auto* const width = window.findChild<QComboBox*>(QStringLiteral("integerWidthCombo"));
    auto* const endian = window.findChild<QComboBox*>(QStringLiteral("integerEndianCombo"));
    auto* const value = window.findChild<QLabel*>(QStringLiteral("integerValueLabel"));

    ASSERT_NE(search, nullptr);
    ASSERT_NE(find_next, nullptr);
    ASSERT_NE(offset, nullptr);
    ASSERT_NE(go_to, nullptr);
    ASSERT_NE(width, nullptr);
    ASSERT_NE(endian, nullptr);
    ASSERT_NE(value, nullptr);

    window.append_packet(make_record());
    packet_table->selectRow(0);
    search->setText(QStringLiteral("c0 a8 01 0a"));
    find_next->click();
    QApplication::processEvents();
    EXPECT_EQ(hex_view->textCursor().selectedText(), QStringLiteral("c0 a8 01 0a"));

    offset->setValue(26);
    width->setCurrentText(QStringLiteral("4"));
    endian->setCurrentText(QStringLiteral("Big endian"));
    go_to->click();
    QApplication::processEvents();
    EXPECT_TRUE(value->text().contains(QStringLiteral("3232235786")));
    EXPECT_TRUE(value->text().contains(QStringLiteral("0xc0a8010a")));
}

}  // namespace

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", QByteArrayLiteral("offscreen"));
    QApplication application{argc, argv};
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

