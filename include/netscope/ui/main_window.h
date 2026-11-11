#pragma once

#include "netscope/capture/capture_runner.h"
#include "netscope/capture/packet_merger.h"
#include "netscope/analysis/display_filter.h"
#include "netscope/analysis/reverse_dns.h"
#include "netscope/analysis/tcp_flow.h"
#include "netscope/analysis/traffic_statistics.h"
#include "netscope/packet/packet_repository.h"

#include <QMainWindow>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

class QPlainTextEdit;
class QAction;
class QComboBox;
class QLabel;
class QPieSeries;
class QLineEdit;
class QStandardItemModel;
class QSpinBox;
class QTableView;
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
    main_window(
        capture::capture_runner::opener opener,
        analysis::reverse_dns_resolver::lookup dns_lookup,
        QWidget* parent = nullptr);
    ~main_window() override;

    void append_packet(std::shared_ptr<const packet::packet_record> packet);
    void load_pcap(const std::filesystem::path& path);
    void save_pcap(const std::filesystem::path& path) const;

private:
    void show_packet(std::size_t index);
    void select_byte_range(std::size_t offset, std::size_t length, bool notify);
    void update_integer_value(std::size_t offset);
    void enqueue_captured_packet(capture::interface_packet packet);
    void drain_captured_packets(bool flush_all);
    void stop_capture();
    void apply_display_filter();
    void refresh_flow_view();
    void refresh_statistics_view();

    QStandardItemModel* packet_model_{nullptr};
    QStandardItemModel* flow_model_{nullptr};
    QTableView* flow_table_{nullptr};
    QPlainTextEdit* flow_data_{nullptr};
    QLabel* statistics_packet_count_{nullptr};
    QLabel* statistics_byte_count_{nullptr};
    QLabel* statistics_rate_{nullptr};
    QPieSeries* protocol_series_{nullptr};
    QPlainTextEdit* statistics_top_{nullptr};
    QTreeWidget* protocol_tree_{nullptr};
    QPlainTextEdit* hex_view_{nullptr};
    QComboBox* integer_width_{nullptr};
    QComboBox* integer_endian_{nullptr};
    QLabel* integer_value_{nullptr};
    QSpinBox* offset_spin_{nullptr};
    QLineEdit* display_filter_edit_{nullptr};
    QAction* start_action_{nullptr};
    QAction* pause_action_{nullptr};
    QAction* stop_action_{nullptr};
    std::vector<std::shared_ptr<const packet::packet_record>> packets_;
    std::vector<int> byte_hex_positions_;
    std::optional<std::size_t> displayed_packet_index_;
    std::optional<std::size_t> current_byte_offset_;
    capture::capture_runner capture_runner_;
    analysis::reverse_dns_resolver reverse_dns_;
    analysis::tcp_flow_tracker flow_tracker_;
    analysis::traffic_statistics statistics_;
    capture::packet_merger packet_merger_;
    packet::packet_repository repository_{100000U};
    std::mutex captured_mutex_;
    std::vector<capture::interface_packet> captured_pending_;
    std::atomic<bool> drain_scheduled_{false};
    bool merge_flush_scheduled_{false};
    std::optional<std::chrono::system_clock::time_point> latest_capture_time_;
    int current_snapshot_length_{262144};
    std::optional<analysis::display_filter> display_filter_;
};

}  // namespace netscope::ui

