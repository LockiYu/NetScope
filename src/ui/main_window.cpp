#include "netscope/ui/main_window.h"

#include "netscope/capture/live_capture.h"
#include "netscope/packet/packet_repository.h"

#include <QAction>
#include <QComboBox>
#include <QDockWidget>
#include <QBrush>
#include <QColor>
#include <QDateTime>
#include <QFontDatabase>
#include <QFormLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStandardItemModel>
#include <QItemSelectionModel>
#include <QStringList>
#include <QStatusBar>
#include <QTableView>
#include <QToolBar>
#include <QTreeWidget>
#include <QTextCursor>
#include <QVBoxLayout>
#include <QWidget>

#include <exception>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <optional>
#include <string>

namespace {

QColor protocol_color(const std::string& protocol) {
    if (protocol == "TCP") {
        return QColor{218, 235, 249};
    }
    if (protocol == "UDP") {
        return QColor{234, 225, 247};
    }
    if (protocol == "ICMP" || protocol == "ICMPv6") {
        return QColor{249, 224, 224};
    }
    if (protocol == "ARP") {
        return QColor{251, 232, 210};
    }
    return QColor{239, 241, 243};
}

QString absolute_time(
    const std::chrono::system_clock::time_point timestamp) {
    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
    return QDateTime::fromMSecsSinceEpoch(milliseconds)
        .toLocalTime()
        .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
}

struct formatted_hex {
    QString text;
    std::vector<int> byte_positions;
};

formatted_hex format_hex(const std::vector<std::uint8_t>& bytes) {
    formatted_hex output;
    output.byte_positions.reserve(bytes.size());
    constexpr std::size_t bytes_per_line{16U};
    for (std::size_t offset = 0U; offset < bytes.size(); offset += bytes_per_line) {
        output.text += QStringLiteral("%1  ").arg(
            static_cast<qulonglong>(offset), 6, 16, QLatin1Char('0'));
        for (std::size_t column = 0U; column < bytes_per_line; ++column) {
            if (offset + column < bytes.size()) {
                output.byte_positions.push_back(static_cast<int>(output.text.size()));
                output.text += QStringLiteral("%1 ").arg(
                    static_cast<unsigned int>(bytes[offset + column]),
                    2,
                    16,
                    QLatin1Char('0'));
            } else {
                output.text += QStringLiteral("   ");
            }
            if (column == 7U) {
                output.text += QLatin1Char(' ');
            }
        }
        output.text += QStringLiteral(" |");
        for (std::size_t column = 0U;
             column < bytes_per_line && offset + column < bytes.size();
             ++column) {
            const auto value = bytes[offset + column];
            output.text += QLatin1Char{
                std::isprint(static_cast<unsigned char>(value)) != 0
                    ? static_cast<char>(value)
                    : '.'};
        }
        output.text += QStringLiteral("|\n");
    }
    return output;
}

void add_protocol_node(
    QTreeWidget* const tree,
    QTreeWidgetItem* const parent,
    const netscope::protocol::protocol_node& node) {
    auto* const item = parent == nullptr
        ? new QTreeWidgetItem{tree}
        : new QTreeWidgetItem{parent};
    item->setText(0, QString::fromStdString(node.name));
    item->setText(
        1,
        QStringLiteral("%1 bytes at offset %2")
            .arg(static_cast<qulonglong>(node.bytes.length))
            .arg(static_cast<qulonglong>(node.bytes.offset)));
    item->setData(0, Qt::UserRole, static_cast<qulonglong>(node.bytes.offset));
    item->setData(0, Qt::UserRole + 1, static_cast<qulonglong>(node.bytes.length));
    item->setData(0, Qt::UserRole + 2, false);

    for (const auto& field : node.fields) {
        auto* const field_item = new QTreeWidgetItem{item};
        field_item->setText(0, QString::fromStdString(field.name));
        field_item->setText(1, QString::fromStdString(field.display_value));
        field_item->setData(
            0, Qt::UserRole, static_cast<qulonglong>(field.bytes.offset));
        field_item->setData(
            0, Qt::UserRole + 1, static_cast<qulonglong>(field.bytes.length));
        field_item->setData(0, Qt::UserRole + 2, true);
        if (!field.warnings.empty()) {
            field_item->setToolTip(1, QString::fromStdString(field.warnings.front()));
        }
    }
    for (const auto& child : node.children) {
        add_protocol_node(tree, item, child);
    }
}

QTreeWidgetItem* find_tree_item(
    QTreeWidgetItem* const root,
    const netscope::protocol::range_match& match) {
    const auto offset = root->data(0, Qt::UserRole).toULongLong();
    const auto length = root->data(0, Qt::UserRole + 1).toULongLong();
    const auto is_field = root->data(0, Qt::UserRole + 2).toBool();
    if (offset == match.bytes.offset && length == match.bytes.length &&
        is_field == match.is_field && root->text(0) == QString::fromStdString(match.name)) {
        return root;
    }
    for (int index = 0; index < root->childCount(); ++index) {
        if (auto* const item = find_tree_item(root->child(index), match); item != nullptr) {
            return item;
        }
    }
    return nullptr;
}

QTreeWidgetItem* find_tree_item(
    QTreeWidget* const tree,
    const netscope::protocol::range_match& match) {
    for (int index = 0; index < tree->topLevelItemCount(); ++index) {
        if (auto* const item = find_tree_item(tree->topLevelItem(index), match);
            item != nullptr) {
            return item;
        }
    }
    return nullptr;
}

std::optional<std::size_t> byte_at_text_position(
    const std::vector<int>& positions,
    const int text_position) {
    const auto after = std::upper_bound(positions.begin(), positions.end(), text_position);
    if (after == positions.begin()) {
        return std::nullopt;
    }
    const auto candidate = std::prev(after);
    if (text_position > *candidate + 1) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(std::distance(positions.begin(), candidate));
}

}  // namespace

namespace netscope::ui {

main_window::main_window(QWidget* parent) : QMainWindow{parent} {
    setWindowTitle(QStringLiteral("NetScope"));
    setMinimumSize(960, 640);

    auto* const toolbar = addToolBar(QStringLiteral("Capture"));
    toolbar->setObjectName(QStringLiteral("captureToolBar"));
    toolbar->setMovable(false);

    auto* const start_action = toolbar->addAction(QStringLiteral("Start"));
    start_action->setObjectName(QStringLiteral("startCaptureAction"));
    start_action->setToolTip(QStringLiteral("Start capture on selected interfaces"));
    auto* const pause_action = toolbar->addAction(QStringLiteral("Pause"));
    pause_action->setObjectName(QStringLiteral("pauseCaptureAction"));
    pause_action->setToolTip(QStringLiteral("Pause packet collection"));
    auto* const stop_action = toolbar->addAction(QStringLiteral("Stop"));
    stop_action->setObjectName(QStringLiteral("stopCaptureAction"));
    stop_action->setToolTip(QStringLiteral("Stop the current capture"));
    pause_action->setEnabled(false);
    stop_action->setEnabled(false);

    toolbar->addSeparator();
    toolbar->addWidget(new QLabel{QStringLiteral("Capture filter:"), toolbar});
    auto* const filter_edit = new QLineEdit{toolbar};
    filter_edit->setObjectName(QStringLiteral("captureFilterEdit"));
    filter_edit->setPlaceholderText(QStringLiteral("tcp and port 443"));
    filter_edit->setClearButtonEnabled(true);
    filter_edit->setMinimumWidth(260);
    toolbar->addWidget(filter_edit);

    auto* const workspace = new QSplitter{Qt::Vertical, this};
    workspace->setObjectName(QStringLiteral("workspaceSplitter"));

    auto* const packet_table = new QTableView{workspace};
    packet_table->setObjectName(QStringLiteral("packetTable"));
    packet_model_ = new QStandardItemModel{packet_table};
    packet_model_->setHorizontalHeaderLabels({
        QStringLiteral("No."),
        QStringLiteral("Time"),
        QStringLiteral("Interface"),
        QStringLiteral("Source"),
        QStringLiteral("Source Port"),
        QStringLiteral("Destination"),
        QStringLiteral("Destination Port"),
        QStringLiteral("Protocol"),
        QStringLiteral("Length"),
        QStringLiteral("Info"),
    });
    packet_table->setModel(packet_model_);
    packet_table->setSortingEnabled(true);
    packet_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    packet_table->setSelectionMode(QAbstractItemView::SingleSelection);
    packet_table->setAlternatingRowColors(true);
    packet_table->verticalHeader()->setVisible(false);
    packet_table->horizontalHeader()->setSectionsMovable(true);
    packet_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    packet_table->horizontalHeader()->setStretchLastSection(true);

    auto* const details = new QSplitter{Qt::Horizontal, workspace};
    details->setObjectName(QStringLiteral("detailsSplitter"));
    protocol_tree_ = new QTreeWidget{details};
    protocol_tree_->setObjectName(QStringLiteral("protocolTree"));
    protocol_tree_->setColumnCount(2);
    protocol_tree_->setHeaderLabels({QStringLiteral("Field"), QStringLiteral("Value")});
    protocol_tree_->setAlternatingRowColors(true);
    protocol_tree_->header()->setStretchLastSection(true);

    hex_view_ = new QPlainTextEdit{details};
    hex_view_->setObjectName(QStringLiteral("hexView"));
    hex_view_->setReadOnly(true);
    hex_view_->setLineWrapMode(QPlainTextEdit::NoWrap);
    hex_view_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    hex_view_->setPlaceholderText(QStringLiteral(
        "Select a packet to inspect its hexadecimal and ASCII representation."));
    details->setSizes({420, 540});
    workspace->setSizes({360, 280});
    setCentralWidget(workspace);

    auto* const capture_dock = new QDockWidget{QStringLiteral("Capture Interfaces"), this};
    capture_dock->setObjectName(QStringLiteral("captureDock"));
    capture_dock->setAllowedAreas(Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea);
    auto* const dock_contents = new QWidget{capture_dock};
    auto* const dock_layout = new QVBoxLayout{dock_contents};
    auto* const interface_list = new QListWidget{dock_contents};
    interface_list->setObjectName(QStringLiteral("interfaceList"));
    interface_list->setAlternatingRowColors(true);

    try {
        for (const auto& interface : capture::list_network_interfaces()) {
            auto* const item = new QListWidgetItem{
                QString::fromStdString(interface.name), interface_list};
            item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
            item->setCheckState(
                capture::should_select_by_default(interface) ? Qt::Checked : Qt::Unchecked);
            QString tooltip = QString::fromStdString(interface.description);
            for (const auto& address : interface.addresses) {
                if (!tooltip.isEmpty()) {
                    tooltip += QLatin1Char('\n');
                }
                tooltip += QString::fromStdString(address.address);
            }
            if (interface.is_tunnel) {
                tooltip += QStringLiteral("\nTunnel/VPN interface — excluded by default");
            }
            item->setToolTip(tooltip);
        }
    } catch (const std::exception& error) {
        auto* const item = new QListWidgetItem{
            QStringLiteral("Interface discovery failed"), interface_list};
        item->setFlags(item->flags() & ~Qt::ItemIsEnabled);
        item->setToolTip(QString::fromUtf8(error.what()));
    }
    dock_layout->addWidget(interface_list);

    auto* const settings_layout = new QFormLayout{};
    auto* const snap_length = new QComboBox{dock_contents};
    snap_length->setObjectName(QStringLiteral("snapshotLengthCombo"));
    snap_length->setEditable(true);
    snap_length->addItems({
        QStringLiteral("262144"),
        QStringLiteral("65535"),
        QStringLiteral("4096"),
        QStringLiteral("256"),
    });
    snap_length->setToolTip(QStringLiteral("Bytes captured from each packet"));
    settings_layout->addRow(QStringLiteral("Capture length"), snap_length);
    dock_layout->addLayout(settings_layout);
    capture_dock->setWidget(dock_contents);
    addDockWidget(Qt::LeftDockWidgetArea, capture_dock);

    statusBar()->showMessage(QStringLiteral("Ready — select one or more interfaces"));

    connect(
        packet_table->selectionModel(),
        &QItemSelectionModel::currentRowChanged,
        this,
        [this](const QModelIndex& current) {
            if (!current.isValid()) {
                return;
            }
            const auto stored_index = packet_model_->index(current.row(), 0)
                                          .data(Qt::UserRole)
                                          .toULongLong();
            show_packet(static_cast<std::size_t>(stored_index));
        });

    connect(
        protocol_tree_,
        &QTreeWidget::currentItemChanged,
        this,
        [this](QTreeWidgetItem* const current) {
            if (current == nullptr || byte_hex_positions_.empty()) {
                return;
            }
            const auto offset = static_cast<std::size_t>(
                current->data(0, Qt::UserRole).toULongLong());
            const auto length = static_cast<std::size_t>(
                current->data(0, Qt::UserRole + 1).toULongLong());
            if (length == 0U || offset >= byte_hex_positions_.size() ||
                length > byte_hex_positions_.size() - offset) {
                return;
            }
            const QSignalBlocker blocker{hex_view_};
            QTextCursor cursor{hex_view_->document()};
            cursor.setPosition(byte_hex_positions_[offset]);
            cursor.setPosition(
                byte_hex_positions_[offset + length - 1U] + 2,
                QTextCursor::KeepAnchor);
            hex_view_->setTextCursor(cursor);
            hex_view_->ensureCursorVisible();
        });

    connect(
        hex_view_,
        &QPlainTextEdit::selectionChanged,
        this,
        [this] {
            if (!displayed_packet_index_.has_value()) {
                return;
            }
            const auto byte_offset = byte_at_text_position(
                byte_hex_positions_, hex_view_->textCursor().position());
            if (!byte_offset.has_value()) {
                return;
            }
            const auto match = protocol::find_most_specific_range(
                packets_[displayed_packet_index_.value()]->analysis,
                byte_offset.value());
            if (!match.has_value()) {
                return;
            }
            if (auto* const item = find_tree_item(protocol_tree_, match.value());
                item != nullptr) {
                const QSignalBlocker blocker{protocol_tree_};
                protocol_tree_->setCurrentItem(item);
                protocol_tree_->scrollToItem(item);
            }
        });
}

void main_window::append_packet(std::shared_ptr<const packet::packet_record> packet) {
    if (!packet) {
        return;
    }
    const auto stored_index = packets_.size();
    packets_.push_back(std::move(packet));
    const auto& record = *packets_.back();

    QStringList interfaces;
    for (const auto& interface : record.capture.interfaces) {
        interfaces.push_back(QString::fromStdString(interface));
    }
    const QList<QStandardItem*> row{
        new QStandardItem{QString::number(record.number)},
        new QStandardItem{absolute_time(record.capture.packet.timestamp)},
        new QStandardItem{interfaces.join(QStringLiteral(", "))},
        new QStandardItem{QString::fromStdString(record.source)},
        new QStandardItem{},
        new QStandardItem{QString::fromStdString(record.destination)},
        new QStandardItem{},
        new QStandardItem{QString::fromStdString(record.protocol)},
        new QStandardItem{QString::number(record.capture.packet.captured_length)},
        new QStandardItem{QString::fromStdString(record.information)},
    };
    const QBrush background{protocol_color(record.protocol)};
    for (auto* const item : row) {
        item->setEditable(false);
        item->setBackground(background);
        item->setData(static_cast<qulonglong>(stored_index), Qt::UserRole);
    }
    packet_model_->appendRow(row);
}

void main_window::show_packet(const std::size_t index) {
    if (index >= packets_.size()) {
        return;
    }
    const auto& record = *packets_[index];
    displayed_packet_index_ = index;
    protocol_tree_->clear();
    add_protocol_node(protocol_tree_, nullptr, record.analysis);
    protocol_tree_->expandToDepth(1);
    auto formatted = format_hex(record.capture.packet.bytes);
    byte_hex_positions_ = std::move(formatted.byte_positions);
    hex_view_->setPlainText(formatted.text);
}

}  // namespace netscope::ui

