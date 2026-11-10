#pragma once

#include "netscope/capture/capture_runner.h"
#include "netscope/capture/packet_merger.h"
#include "netscope/packet/packet_repository.h"

#include <QMainWindow>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

class QPlainTextEdit;
class QAction;
class QComboBox;
class QLabel;
class QStandardItemModel;
class QSpinBox;
class QTreeWidget;

namespace netscope::packet {
struct packet_record;
}

namespace netscope::ui {

class main_window final : public QMainWindow {
public:
    explicit main_window(QWidget* parent = nullptr);
    explicit main_window(
        capture::capture_runner::opener opener,
        QWidget* parent = nullptr);
    ~main_window() override;

    void append_packet(std::shared_ptr<const packet::packet_record> packet);

private:
    void show_packet(std::size_t index);
    void select_byte_range(std::size_t offset, std::size_t length, bool notify);
    void update_integer_value(std::size_t offset);
    void enqueue_captured_packet(capture::interface_packet packet);
    void drain_captured_packets(bool flush_all);
    void stop_capture();

    QStandardItemModel* packet_model_{nullptr};
    QTreeWidget* protocol_tree_{nullptr};
    QPlainTextEdit* hex_view_{nullptr};
    QComboBox* integer_width_{nullptr};
    QComboBox* integer_endian_{nullptr};
    QLabel* integer_value_{nullptr};
    QSpinBox* offset_spin_{nullptr};
    QAction* start_action_{nullptr};
    QAction* pause_action_{nullptr};
    QAction* stop_action_{nullptr};
    std::vector<std::shared_ptr<const packet::packet_record>> packets_;
    std::vector<int> byte_hex_positions_;
    std::optional<std::size_t> displayed_packet_index_;
    std::optional<std::size_t> current_byte_offset_;
    capture::capture_runner capture_runner_;
    capture::packet_merger packet_merger_;
    packet::packet_repository repository_{100000U};
    std::mutex captured_mutex_;
    std::vector<capture::interface_packet> captured_pending_;
    std::atomic<bool> drain_scheduled_{false};
    bool merge_flush_scheduled_{false};
    std::optional<std::chrono::system_clock::time_point> latest_capture_time_;
};

}  // namespace netscope::ui

