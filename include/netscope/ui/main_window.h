#pragma once

#include <QMainWindow>

#include <cstddef>
#include <memory>
#include <vector>

class QPlainTextEdit;
class QStandardItemModel;
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

    QStandardItemModel* packet_model_{nullptr};
    QTreeWidget* protocol_tree_{nullptr};
    QPlainTextEdit* hex_view_{nullptr};
    std::vector<std::shared_ptr<const packet::packet_record>> packets_;
};

}  // namespace netscope::ui

