#include "netscope/ui/main_window.h"

#include "netscope/capture/capture_runner.h"
#include "netscope/packet/packet_repository.h"

#include <QAction>
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
#include <QTemporaryDir>
#include <QTreeWidget>

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <thread>

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

std::vector<std::uint8_t> sample_bytes() {
    return {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, 0, 0x28, 0, 1, 0x40, 0, 64, 6, 0, 0,
        192, 168, 1, 10, 8, 8, 8, 8,
        0x04, 0xd2, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0,
        0x50, 0x02, 0x40, 0, 0, 0, 0, 0,
    };
}

std::shared_ptr<const netscope::packet::packet_record> make_record() {
    auto bytes = sample_bytes();
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

std::shared_ptr<const netscope::packet::packet_record> make_fragment(
    netscope::packet::packet_repository& repository,
    const std::uint16_t offset_units,
    const bool more,
    const std::string& payload) {
    const auto total = static_cast<std::uint16_t>(20U + payload.size());
    const auto fragment = static_cast<std::uint16_t>(
        (more ? 0x2000U : 0U) | offset_units);
    std::vector<std::uint8_t> bytes{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, static_cast<std::uint8_t>(total >> 8U),
        static_cast<std::uint8_t>(total), 0x12, 0x34,
        static_cast<std::uint8_t>(fragment >> 8U),
        static_cast<std::uint8_t>(fragment), 64, 17, 0, 0,
        10, 0, 0, 1, 10, 0, 0, 2,
    };
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return repository.append(netscope::capture::merged_packet{
        netscope::capture::captured_packet{
            std::chrono::system_clock::now(),
            static_cast<std::uint32_t>(bytes.size()),
            static_cast<std::uint32_t>(bytes.size()),
            std::move(bytes)},
        {"en0"},
    });
}

class ui_packet_backend final : public netscope::capture::capture_backend {
public:
    std::optional<netscope::capture::captured_packet> next_packet() override {
        if (delivered_) {
            return std::nullopt;
        }
        delivered_ = true;
        auto bytes = sample_bytes();
        return netscope::capture::captured_packet{
            std::chrono::system_clock::now(),
            static_cast<std::uint32_t>(bytes.size()),
            static_cast<std::uint32_t>(bytes.size()),
            std::move(bytes),
        };
    }

    void break_capture() noexcept override {}
    netscope::capture::capture_statistics statistics() const override { return {}; }

private:
    bool delivered_{false};
};

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

TEST(main_window_test, connects_capture_actions_to_the_multi_interface_runner) {
    netscope::ui::main_window window{
        [](const std::string& name, const netscope::capture::capture_options&) {
            return netscope::capture::capture_session{
                std::make_unique<ui_packet_backend>(), name};
        }};
    auto* const interfaces = window.findChild<QListWidget*>(QStringLiteral("interfaceList"));
    auto* const table = window.findChild<QTableView*>(QStringLiteral("packetTable"));
    auto* const start = window.findChild<QAction*>(QStringLiteral("startCaptureAction"));
    auto* const stop = window.findChild<QAction*>(QStringLiteral("stopCaptureAction"));

    ASSERT_NE(interfaces, nullptr);
    ASSERT_GT(interfaces->count(), 0);
    for (int index = 0; index < interfaces->count(); ++index) {
        interfaces->item(index)->setCheckState(index == 0 ? Qt::Checked : Qt::Unchecked);
    }

    start->trigger();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    while (table->model()->rowCount() == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        QApplication::processEvents();
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    stop->trigger();
    QApplication::processEvents();

    EXPECT_EQ(table->model()->rowCount(), 1);
    EXPECT_TRUE(start->isEnabled());
    EXPECT_FALSE(stop->isEnabled());
}

TEST(main_window_test, loads_and_saves_pcap_sessions) {
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const auto input = std::filesystem::path{directory.path().toStdString()} / "input.pcap";
    const auto output = std::filesystem::path{directory.path().toStdString()} / "output.pcap";
    auto bytes = sample_bytes();
    netscope::capture::write_pcap_file(
        input,
        1,
        262144,
        {netscope::capture::captured_packet{
            std::chrono::system_clock::now(),
            static_cast<std::uint32_t>(bytes.size()),
            static_cast<std::uint32_t>(bytes.size()),
            std::move(bytes),
        }});
    netscope::ui::main_window window;

    window.load_pcap(input);
    auto* const table = window.findChild<QTableView*>(QStringLiteral("packetTable"));
    ASSERT_EQ(table->model()->rowCount(), 1);

    window.save_pcap(output);
    const auto roundtrip = netscope::capture::read_pcap_file(output);
    ASSERT_EQ(roundtrip.packets.size(), 1U);
    EXPECT_EQ(roundtrip.packets.front().bytes, sample_bytes());
}

TEST(main_window_test, applies_display_filters_without_deleting_packets) {
    netscope::ui::main_window window;
    auto* const table = window.findChild<QTableView*>(QStringLiteral("packetTable"));
    auto* const filter = window.findChild<QLineEdit*>(QStringLiteral("displayFilterEdit"));
    ASSERT_NE(filter, nullptr);
    window.append_packet(make_record());

    filter->setText(QStringLiteral("udp"));
    QMetaObject::invokeMethod(filter, "returnPressed");
    QApplication::processEvents();
    EXPECT_TRUE(table->isRowHidden(0));
    EXPECT_EQ(table->model()->rowCount(), 1);

    filter->setText(QStringLiteral("tcp.dstport == 80"));
    QMetaObject::invokeMethod(filter, "returnPressed");
    QApplication::processEvents();
    EXPECT_FALSE(table->isRowHidden(0));
}

TEST(main_window_test, updates_address_display_after_reverse_dns_without_losing_raw_ip) {
    netscope::ui::main_window window{
        [](const std::string& name, const netscope::capture::capture_options&) {
            return netscope::capture::capture_session{
                std::make_unique<ui_packet_backend>(), name};
        },
        [](const std::string& address) -> std::optional<std::string> {
            return address == "192.168.1.10"
                ? std::optional<std::string>{"client.example"}
                : std::nullopt;
        }};
    auto* const table = window.findChild<QTableView*>(QStringLiteral("packetTable"));
    window.append_packet(make_record());

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    while (!table->model()->index(0, 3).data().toString().contains("client.example") &&
           std::chrono::steady_clock::now() < deadline) {
        QApplication::processEvents();
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }

    EXPECT_TRUE(table->model()->index(0, 3).data().toString().contains("client.example"));
    EXPECT_EQ(
        table->model()->index(0, 3).data(Qt::UserRole + 3).toString(),
        QStringLiteral("192.168.1.10"));
}

TEST(main_window_test, exposes_tracked_tcp_flows_in_a_dedicated_view) {
    netscope::ui::main_window window;
    auto* const flow_table = window.findChild<QTableView*>(QStringLiteral("tcpFlowTable"));
    auto* const flow_data = window.findChild<QPlainTextEdit*>(QStringLiteral("tcpFlowData"));
    ASSERT_NE(flow_table, nullptr);
    ASSERT_NE(flow_data, nullptr);

    window.append_packet(make_record());
    QApplication::processEvents();

    ASSERT_EQ(flow_table->model()->rowCount(), 1);
    EXPECT_TRUE(flow_table->model()->index(0, 1).data().toString().contains("192.168.1.10"));
}

TEST(main_window_test, updates_traffic_statistics_and_protocol_chart) {
    netscope::ui::main_window window;
    auto* const packet_count = window.findChild<QLabel*>(QStringLiteral("statisticsPacketCount"));
    auto* const protocol_chart = window.findChild<QObject*>(QStringLiteral("protocolChart"));
    ASSERT_NE(packet_count, nullptr);
    ASSERT_NE(protocol_chart, nullptr);

    window.append_packet(make_record());
    QApplication::processEvents();

    EXPECT_TRUE(packet_count->text().contains(QStringLiteral("1")));
}

TEST(main_window_test, lists_explainable_anomaly_observations) {
    netscope::ui::main_window window;
    auto* const alerts = window.findChild<QTableView*>(QStringLiteral("anomalyTable"));
    ASSERT_NE(alerts, nullptr);
    netscope::packet::packet_repository repository{1U};
    std::vector<std::uint8_t> bytes{0U, 1U, 2U};
    const auto record = repository.append(netscope::capture::merged_packet{
        netscope::capture::captured_packet{
            std::chrono::system_clock::now(), 3U, 3U, std::move(bytes)},
        {"en0"},
    });

    window.append_packet(record);
    QApplication::processEvents();

    ASSERT_EQ(alerts->model()->rowCount(), 1);
    EXPECT_TRUE(alerts->model()->index(0, 2).data().toString().contains("truncated"));
}

TEST(main_window_test, marks_and_annotates_packets_without_changing_capture_data) {
    netscope::ui::main_window window;
    auto* const table = window.findChild<QTableView*>(QStringLiteral("packetTable"));
    window.append_packet(make_record());

    window.set_packet_annotation(0U, true, "Investigate handshake");

    EXPECT_TRUE(table->model()->index(0, 0).data().toString().startsWith(QStringLiteral("★")));
    EXPECT_EQ(
        table->model()->index(0, 9).data(Qt::ToolTipRole).toString(),
        QStringLiteral("Investigate handshake"));
    EXPECT_EQ(table->model()->rowCount(), 1);
}

TEST(main_window_test, reports_completed_ip_fragment_reassembly) {
    netscope::ui::main_window window;
    auto* const observations = window.findChild<QTableView*>(QStringLiteral("anomalyTable"));
    netscope::packet::packet_repository repository{4U};

    window.append_packet(make_fragment(repository, 0U, true, "ABCDEFGH"));
    window.append_packet(make_fragment(repository, 1U, false, "IJKL"));

    ASSERT_NE(observations, nullptr);
    ASSERT_EQ(observations->model()->rowCount(), 1);
    EXPECT_EQ(
        observations->model()->index(0, 0).data().toString(),
        QStringLiteral("IP fragment reassembly"));
    EXPECT_TRUE(
        observations->model()->index(0, 2).data().toString().contains("12 bytes"));
}

}  // namespace

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", QByteArrayLiteral("offscreen"));
    QApplication application{argc, argv};
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

