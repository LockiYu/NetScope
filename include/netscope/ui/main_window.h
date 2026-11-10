#pragma once

#include <QMainWindow>

#include <cstddef>
#include <memory>
#include <optional>
#include <vector>

class QPlainTextEdit;
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

    void append_packet(std::shared_ptr<const packet::packet_record> packet);

private:
    void show_packet(std::size_t index);
    void select_byte_range(std::size_t offset, std::size_t length, bool notify);
    void update_integer_value(std::size_t offset);

    QStandardItemModel* packet_model_{nullptr};
    QTreeWidget* protocol_tree_{nullptr};
    QPlainTextEdit* hex_view_{nullptr};
    QComboBox* integer_width_{nullptr};
    QComboBox* integer_endian_{nullptr};
    QLabel* integer_value_{nullptr};
    QSpinBox* offset_spin_{nullptr};
    std::vector<std::shared_ptr<const packet::packet_record>> packets_;
    std::vector<int> byte_hex_positions_;
    std::optional<std::size_t> displayed_packet_index_;
    std::optional<std::size_t> current_byte_offset_;
};

}  // namespace netscope::ui

