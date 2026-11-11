#include "netscope/ui/main_window.h"

#include "netscope/capture/live_capture.h"
#include "netscope/analysis/packet_compare.h"
#include "netscope/packet/byte_inspector.h"
#include "netscope/packet/packet_repository.h"

#include <QAction>
#include <QApplication>
#include <QComboBox>
#include <QClipboard>
#include <QCompleter>
#include <QCoreApplication>
#include <QDockWidget>
#include <QBrush>
#include <QColor>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QInputDialog>
#include <QMenu>
#include <QMenuBar>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSettings>
#include <QSplitter>
#include <QSpinBox>
#include <QStandardItemModel>
#include <QItemSelectionModel>
#include <QStringList>
#include <QStringListModel>
#include <QStatusBar>
#include <QTableView>
#include <QToolBar>
#include <QTreeWidget>
#include <QTextCursor>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>
#include <QChart>
#include <QChartView>
#include <QPieSeries>

#include <exception>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

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
    if (protocol == "DNS") {
        return QColor{250, 243, 196};
    }
    if (protocol == "HTTP" || protocol == "DHCP") {
        return QColor{220, 241, 221};
    }
    if (protocol == "TLS") {
        return QColor{218, 229, 238};
    }
    return QColor{239, 241, 243};
}

class address_item final : public QStandardItem {
public:
    using QStandardItem::QStandardItem;

    bool operator<(const QStandardItem& other) const override {
        return data(Qt::UserRole + 3).toString() <
               other.data(Qt::UserRole + 3).toString();
    }
};

QString absolute_time(
    const std::chrono::system_clock::time_point timestamp) {
    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
    return QDateTime::fromMSecsSinceEpoch(milliseconds)
        .toLocalTime()
        .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
}

QString flow_state_name(const netscope::analysis::tcp_flow_state state) {
    switch (state) {
    case netscope::analysis::tcp_flow_state::opening: return QStringLiteral("Opening");
    case netscope::analysis::tcp_flow_state::established: return QStringLiteral("Established");
    case netscope::analysis::tcp_flow_state::half_closed: return QStringLiteral("Half closed");
    case netscope::analysis::tcp_flow_state::closed: return QStringLiteral("Closed");
    case netscope::analysis::tcp_flow_state::reset: return QStringLiteral("Reset");
    }
    return QStringLiteral("Unknown");
}

QString endpoint_text(const netscope::analysis::tcp_endpoint& endpoint) {
    const bool ipv6 = endpoint.address.find(':') != std::string::npos;
    return ipv6
        ? QStringLiteral("[%1]:%2")
              .arg(QString::fromStdString(endpoint.address))
              .arg(endpoint.port)
        : QStringLiteral("%1:%2")
              .arg(QString::fromStdString(endpoint.address))
              .arg(endpoint.port);
}

QString printable_stream(const std::vector<std::uint8_t>& bytes) {
    QString text;
    text.reserve(static_cast<qsizetype>(bytes.size()));
    for (const auto value : bytes) {
        text += std::isprint(static_cast<unsigned char>(value)) != 0
            ? QChar::fromLatin1(static_cast<char>(value))
            : QLatin1Char('.');
    }
    return text;
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

main_window::main_window(QWidget* parent)
    : main_window{
          capture::capture_runner::opener{capture::open_live_capture},
          analysis::reverse_dns_resolver::lookup{
              analysis::reverse_dns_resolver::system_lookup},
          parent} {}

main_window::main_window(
    capture::capture_runner::opener opener,
    QWidget* parent)
    : main_window{
          std::move(opener),
          analysis::reverse_dns_resolver::lookup{
              analysis::reverse_dns_resolver::system_lookup},
          parent} {}

main_window::main_window(
    capture::capture_runner::opener opener,
    analysis::reverse_dns_resolver::lookup dns_lookup,
    QWidget* parent)
    : QMainWindow{parent},
      capture_runner_{std::move(opener)},
      reverse_dns_{std::move(dns_lookup)} {
    setWindowTitle(QStringLiteral("NetScope"));
    setMinimumSize(960, 640);

    auto* const file_menu = menuBar()->addMenu(QStringLiteral("File"));
    auto* const open_action = file_menu->addAction(QStringLiteral("Open PCAP…"));
    open_action->setObjectName(QStringLiteral("openPcapAction"));
    open_action->setShortcut(QKeySequence::Open);
    auto* const save_action = file_menu->addAction(QStringLiteral("Save PCAP As…"));
    save_action->setObjectName(QStringLiteral("savePcapAction"));
    save_action->setShortcut(QKeySequence::SaveAs);
    auto* const save_visible_action = file_menu->addAction(
        QStringLiteral("Export visible packets…"));
    save_visible_action->setObjectName(QStringLiteral("saveVisiblePcapAction"));
    auto* const export_json_action = file_menu->addAction(
        QStringLiteral("Export selected packet as JSON…"));
    export_json_action->setObjectName(QStringLiteral("exportPacketJsonAction"));
    auto* const analysis_menu = menuBar()->addMenu(QStringLiteral("Analysis"));
    auto* const compare_action = analysis_menu->addAction(
        QStringLiteral("Compare selected packets…"));
    compare_action->setObjectName(QStringLiteral("comparePacketsAction"));

    auto* const toolbar = addToolBar(QStringLiteral("Capture"));
    toolbar->setObjectName(QStringLiteral("captureToolBar"));
    toolbar->setMovable(false);

    start_action_ = toolbar->addAction(QStringLiteral("Start"));
    start_action_->setObjectName(QStringLiteral("startCaptureAction"));
    start_action_->setToolTip(QStringLiteral("Start capture on selected interfaces"));
    pause_action_ = toolbar->addAction(QStringLiteral("Pause"));
    pause_action_->setObjectName(QStringLiteral("pauseCaptureAction"));
    pause_action_->setToolTip(QStringLiteral("Pause packet collection"));
    stop_action_ = toolbar->addAction(QStringLiteral("Stop"));
    stop_action_->setObjectName(QStringLiteral("stopCaptureAction"));
    stop_action_->setToolTip(QStringLiteral("Stop the current capture"));
    pause_action_->setEnabled(false);
    stop_action_->setEnabled(false);

    toolbar->addSeparator();
    toolbar->addWidget(new QLabel{QStringLiteral("Capture filter:"), toolbar});
    auto* const filter_edit = new QLineEdit{toolbar};
    filter_edit->setObjectName(QStringLiteral("captureFilterEdit"));
    filter_edit->setPlaceholderText(QStringLiteral("tcp and port 443"));
    filter_edit->setClearButtonEnabled(true);
    filter_edit->setMinimumWidth(260);
    toolbar->addWidget(filter_edit);
    QStringList filter_suggestions{
        QStringLiteral("tcp"), QStringLiteral("udp"), QStringLiteral("icmp"),
        QStringLiteral("icmp6"), QStringLiteral("arp"), QStringLiteral("port 53"),
        QStringLiteral("tcp port 80"), QStringLiteral("tcp port 443"),
        QStringLiteral("not port 22"),
    };
    if (!QCoreApplication::organizationName().isEmpty()) {
        QSettings settings;
        const auto history = settings.value(QStringLiteral("capture/filterHistory")).toStringList();
        const auto favorites = settings.value(QStringLiteral("capture/filterFavorites")).toStringList();
        for (const auto& value : history + favorites) {
            if (!value.isEmpty() && !filter_suggestions.contains(value)) {
                filter_suggestions.push_back(value);
            }
        }
    }
    auto* const filter_completer = new QCompleter{filter_suggestions, filter_edit};
    filter_completer->setCaseSensitivity(Qt::CaseInsensitive);
    filter_completer->setFilterMode(Qt::MatchContains);
    filter_edit->setCompleter(filter_completer);
    auto* const favorite_filter_action = toolbar->addAction(QStringLiteral("★"));
    favorite_filter_action->setObjectName(QStringLiteral("captureFilterFavoriteAction"));
    favorite_filter_action->setToolTip(QStringLiteral("Add current capture filter to favorites"));
    toolbar->addSeparator();
    toolbar->addWidget(new QLabel{QStringLiteral("Display filter:"), toolbar});
    display_filter_edit_ = new QLineEdit{toolbar};
    display_filter_edit_->setObjectName(QStringLiteral("displayFilterEdit"));
    display_filter_edit_->setPlaceholderText(
        QStringLiteral("tcp and ip.src == 192.168.1.1"));
    display_filter_edit_->setClearButtonEnabled(true);
    display_filter_edit_->setMinimumWidth(280);
    toolbar->addWidget(display_filter_edit_);

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
    packet_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    packet_table->setAlternatingRowColors(true);
    packet_table->verticalHeader()->setVisible(false);
    packet_table->horizontalHeader()->setSectionsMovable(true);
    packet_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    packet_table->horizontalHeader()->setStretchLastSection(true);
    packet_table->setContextMenuPolicy(Qt::CustomContextMenu);
    packet_table->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);

    auto* const details = new QSplitter{Qt::Horizontal, workspace};
    details->setObjectName(QStringLiteral("detailsSplitter"));
    protocol_tree_ = new QTreeWidget{details};
    protocol_tree_->setObjectName(QStringLiteral("protocolTree"));
    protocol_tree_->setColumnCount(2);
    protocol_tree_->setHeaderLabels({QStringLiteral("Field"), QStringLiteral("Value")});
    protocol_tree_->setAlternatingRowColors(true);
    protocol_tree_->header()->setStretchLastSection(true);

    auto* const hex_panel = new QWidget{details};
    auto* const hex_layout = new QVBoxLayout{hex_panel};
    hex_layout->setContentsMargins(0, 0, 0, 0);
    auto* const search_layout = new QHBoxLayout{};
    auto* const search_mode = new QComboBox{hex_panel};
    search_mode->setObjectName(QStringLiteral("hexSearchModeCombo"));
    search_mode->addItems({QStringLiteral("Hex"), QStringLiteral("Text")});
    auto* const search_edit = new QLineEdit{hex_panel};
    search_edit->setObjectName(QStringLiteral("hexSearchEdit"));
    search_edit->setPlaceholderText(QStringLiteral("Hex bytes or text"));
    auto* const find_next = new QPushButton{QStringLiteral("Find next"), hex_panel};
    find_next->setObjectName(QStringLiteral("hexFindNextButton"));
    search_layout->addWidget(search_mode);
    search_layout->addWidget(search_edit, 1);
    search_layout->addWidget(find_next);
    hex_layout->addLayout(search_layout);

    auto* const inspect_layout = new QHBoxLayout{};
    inspect_layout->addWidget(new QLabel{QStringLiteral("Offset"), hex_panel});
    offset_spin_ = new QSpinBox{hex_panel};
    offset_spin_->setObjectName(QStringLiteral("hexOffsetSpin"));
    offset_spin_->setRange(0, 0);
    auto* const go_to = new QPushButton{QStringLiteral("Go"), hex_panel};
    go_to->setObjectName(QStringLiteral("hexGoButton"));
    integer_width_ = new QComboBox{hex_panel};
    integer_width_->setObjectName(QStringLiteral("integerWidthCombo"));
    integer_width_->addItems({QStringLiteral("1"), QStringLiteral("2"),
                              QStringLiteral("4"), QStringLiteral("8")});
    integer_endian_ = new QComboBox{hex_panel};
    integer_endian_->setObjectName(QStringLiteral("integerEndianCombo"));
    integer_endian_->addItems(
        {QStringLiteral("Big endian"), QStringLiteral("Little endian")});
    integer_value_ = new QLabel{QStringLiteral("No byte selected"), hex_panel};
    integer_value_->setObjectName(QStringLiteral("integerValueLabel"));
    integer_value_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    inspect_layout->addWidget(offset_spin_);
    inspect_layout->addWidget(go_to);
    inspect_layout->addSpacing(8);
    inspect_layout->addWidget(new QLabel{QStringLiteral("Integer"), hex_panel});
    inspect_layout->addWidget(integer_width_);
    inspect_layout->addWidget(integer_endian_);
    inspect_layout->addWidget(integer_value_, 1);
    hex_layout->addLayout(inspect_layout);

    hex_view_ = new QPlainTextEdit{hex_panel};
    hex_view_->setObjectName(QStringLiteral("hexView"));
    hex_view_->setReadOnly(true);
    hex_view_->setLineWrapMode(QPlainTextEdit::NoWrap);
    hex_view_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    hex_view_->setPlaceholderText(QStringLiteral(
        "Select a packet to inspect its hexadecimal and ASCII representation."));
    hex_layout->addWidget(hex_view_, 1);
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

    auto* const flow_dock = new QDockWidget{QStringLiteral("TCP Flows"), this};
    flow_dock->setObjectName(QStringLiteral("tcpFlowDock"));
    flow_dock->setAllowedAreas(Qt::BottomDockWidgetArea | Qt::RightDockWidgetArea);
    auto* const flow_panel = new QSplitter{Qt::Vertical, flow_dock};
    flow_table_ = new QTableView{flow_panel};
    flow_table_->setObjectName(QStringLiteral("tcpFlowTable"));
    flow_model_ = new QStandardItemModel{flow_table_};
    flow_model_->setHorizontalHeaderLabels({
        QStringLiteral("ID"), QStringLiteral("Client"), QStringLiteral("Server"),
        QStringLiteral("State"), QStringLiteral("Packets"), QStringLiteral("Bytes"),
        QStringLiteral("RTT"), QStringLiteral("Retrans"), QStringLiteral("Out-of-order"),
    });
    flow_table_->setModel(flow_model_);
    flow_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    flow_table_->setSelectionMode(QAbstractItemView::SingleSelection);
    flow_table_->setSortingEnabled(true);
    flow_table_->horizontalHeader()->setStretchLastSection(true);
    flow_table_->setContextMenuPolicy(Qt::CustomContextMenu);
    flow_data_ = new QPlainTextEdit{flow_panel};
    flow_data_->setObjectName(QStringLiteral("tcpFlowData"));
    flow_data_->setReadOnly(true);
    flow_data_->setLineWrapMode(QPlainTextEdit::NoWrap);
    flow_data_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    flow_data_->setPlaceholderText(QStringLiteral("Select a TCP flow to inspect reassembled data."));
    flow_panel->setSizes({180, 120});
    flow_dock->setWidget(flow_panel);
    addDockWidget(Qt::BottomDockWidgetArea, flow_dock);

    auto* const statistics_dock = new QDockWidget{QStringLiteral("Traffic Statistics"), this};
    statistics_dock->setObjectName(QStringLiteral("statisticsDock"));
    statistics_dock->setAllowedAreas(Qt::RightDockWidgetArea | Qt::BottomDockWidgetArea);
    auto* const statistics_panel = new QWidget{statistics_dock};
    auto* const statistics_layout = new QVBoxLayout{statistics_panel};
    statistics_packet_count_ = new QLabel{QStringLiteral("Packets: 0"), statistics_panel};
    statistics_packet_count_->setObjectName(QStringLiteral("statisticsPacketCount"));
    statistics_byte_count_ = new QLabel{QStringLiteral("Bytes: 0"), statistics_panel};
    statistics_byte_count_->setObjectName(QStringLiteral("statisticsByteCount"));
    statistics_rate_ = new QLabel{QStringLiteral("Rate: 0 packets/s, 0 B/s"), statistics_panel};
    statistics_rate_->setObjectName(QStringLiteral("statisticsRate"));
    statistics_layout->addWidget(statistics_packet_count_);
    statistics_layout->addWidget(statistics_byte_count_);
    statistics_layout->addWidget(statistics_rate_);
    protocol_series_ = new QPieSeries{statistics_panel};
    auto* const protocol_chart = new QChart{};
    protocol_chart->addSeries(protocol_series_);
    protocol_chart->setTitle(QStringLiteral("Protocol distribution"));
    protocol_chart->legend()->setVisible(true);
    auto* const protocol_chart_view = new QChartView{protocol_chart, statistics_panel};
    protocol_chart_view->setObjectName(QStringLiteral("protocolChart"));
    protocol_chart_view->setRenderHint(QPainter::Antialiasing);
    protocol_chart_view->setMinimumHeight(180);
    statistics_layout->addWidget(protocol_chart_view);
    statistics_top_ = new QPlainTextEdit{statistics_panel};
    statistics_top_->setObjectName(QStringLiteral("statisticsTop"));
    statistics_top_->setReadOnly(true);
    statistics_top_->setMaximumHeight(160);
    statistics_layout->addWidget(statistics_top_);
    statistics_dock->setWidget(statistics_panel);
    addDockWidget(Qt::RightDockWidgetArea, statistics_dock);

    auto* const anomaly_dock = new QDockWidget{QStringLiteral("Observations"), this};
    anomaly_dock->setObjectName(QStringLiteral("anomalyDock"));
    anomaly_dock->setAllowedAreas(Qt::BottomDockWidgetArea | Qt::RightDockWidgetArea);
    auto* const anomaly_table = new QTableView{anomaly_dock};
    anomaly_table->setObjectName(QStringLiteral("anomalyTable"));
    anomaly_model_ = new QStandardItemModel{anomaly_table};
    anomaly_model_->setHorizontalHeaderLabels({
        QStringLiteral("Rule"), QStringLiteral("Observation"),
        QStringLiteral("Evidence"), QStringLiteral("Related item"),
    });
    anomaly_table->setModel(anomaly_model_);
    anomaly_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    anomaly_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    anomaly_table->horizontalHeader()->setStretchLastSection(true);
    anomaly_dock->setWidget(anomaly_table);
    addDockWidget(Qt::BottomDockWidgetArea, anomaly_dock);

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
    connect(compare_action, &QAction::triggered, this, [this, packet_table] {
        const auto rows = packet_table->selectionModel()->selectedRows(0);
        if (rows.size() != 2) {
            statusBar()->showMessage(QStringLiteral("Select exactly two packets to compare"), 4000);
            return;
        }
        const auto left_index = static_cast<std::size_t>(
            rows[0].data(Qt::UserRole).toULongLong());
        const auto right_index = static_cast<std::size_t>(
            rows[1].data(Qt::UserRole).toULongLong());
        if (left_index >= packets_.size() || right_index >= packets_.size()) {
            return;
        }
        const auto differences = analysis::compare_protocol_trees(
            packets_[left_index]->analysis,
            packets_[right_index]->analysis);
        QDialog dialog{this};
        dialog.setWindowTitle(QStringLiteral("Compare packets %1 and %2")
            .arg(static_cast<qulonglong>(packets_[left_index]->number))
            .arg(static_cast<qulonglong>(packets_[right_index]->number)));
        dialog.resize(900, 520);
        auto* const layout = new QVBoxLayout{&dialog};
        auto* const table = new QTableView{&dialog};
        auto* const model = new QStandardItemModel{table};
        model->setHorizontalHeaderLabels({
            QStringLiteral("Field path"),
            QStringLiteral("Packet %1").arg(static_cast<qulonglong>(packets_[left_index]->number)),
            QStringLiteral("Packet %1").arg(static_cast<qulonglong>(packets_[right_index]->number)),
        });
        for (const auto& difference : differences) {
            QList<QStandardItem*> row{
                new QStandardItem{QString::fromStdString(difference.path)},
                new QStandardItem{QString::fromStdString(difference.left_value)},
                new QStandardItem{QString::fromStdString(difference.right_value)},
            };
            for (auto* const item : row) {
                item->setEditable(false);
            }
            model->appendRow(row);
        }
        table->setModel(model);
        table->setAlternatingRowColors(true);
        table->horizontalHeader()->setStretchLastSection(true);
        layout->addWidget(new QLabel{
            differences.empty()
                ? QStringLiteral("No protocol-field differences")
                : QStringLiteral("%1 differing field(s)").arg(differences.size()),
            &dialog});
        layout->addWidget(table, 1);
        auto* const buttons = new QDialogButtonBox{QDialogButtonBox::Close, &dialog};
        connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        layout->addWidget(buttons);
        dialog.exec();
    });

    connect(
        packet_table,
        &QTableView::customContextMenuRequested,
        this,
        [this, packet_table](const QPoint& position) {
            const auto index = packet_table->indexAt(position);
            if (!index.isValid()) {
                return;
            }
            packet_table->selectRow(index.row());
            const auto stored_index = static_cast<std::size_t>(
                packet_model_->index(index.row(), 0)
                    .data(Qt::UserRole)
                    .toULongLong());
            const auto annotation = annotations_.find(stored_index);
            const bool marked = annotation != annotations_.end() && annotation->second.marked;

            QMenu menu{packet_table};
            auto* const mark_action = menu.addAction(
                marked ? QStringLiteral("Unmark packet") : QStringLiteral("Mark packet"));
            auto* const note_action = menu.addAction(QStringLiteral("Add or edit note…"));
            menu.addSeparator();
            auto* const copy_action = menu.addAction(QStringLiteral("Copy row"));
            menu.addSeparator();
            auto* const source_filter = menu.addAction(QStringLiteral("Filter by source"));
            auto* const destination_filter = menu.addAction(
                QStringLiteral("Filter by destination"));
            auto* const protocol_filter = menu.addAction(QStringLiteral("Filter by protocol"));
            const auto* const chosen = menu.exec(packet_table->viewport()->mapToGlobal(position));
            if (chosen == nullptr) {
                return;
            }
            const auto existing_note = annotation == annotations_.end()
                ? std::string{}
                : annotation->second.note;
            if (chosen == mark_action) {
                set_packet_annotation(stored_index, !marked, existing_note);
                return;
            }
            if (chosen == note_action) {
                bool accepted{false};
                const auto note = QInputDialog::getMultiLineText(
                    this,
                    QStringLiteral("Packet note"),
                    QStringLiteral("Note:"),
                    QString::fromStdString(existing_note),
                    &accepted);
                if (accepted) {
                    set_packet_annotation(stored_index, marked, note.toStdString());
                }
                return;
            }
            if (chosen == copy_action) {
                QStringList values;
                for (int column = 0; column < packet_model_->columnCount(); ++column) {
                    values.push_back(packet_model_->index(index.row(), column).data().toString());
                }
                QApplication::clipboard()->setText(values.join(QLatin1Char('\t')));
                return;
            }
            QString filter;
            if (chosen == source_filter) {
                filter = QStringLiteral("ip.src == %1").arg(
                    packet_model_->index(index.row(), 3)
                        .data(Qt::UserRole + 3).toString());
            } else if (chosen == destination_filter) {
                filter = QStringLiteral("ip.dst == %1").arg(
                    packet_model_->index(index.row(), 5)
                        .data(Qt::UserRole + 3).toString());
            } else if (chosen == protocol_filter) {
                filter = packet_model_->index(index.row(), 7).data().toString().toLower();
            }
            if (!filter.isEmpty()) {
                display_filter_edit_->setText(filter);
                apply_display_filter();
            }
        });

    connect(
        packet_table->horizontalHeader(),
        &QHeaderView::customContextMenuRequested,
        this,
        [packet_table](const QPoint& position) {
            QMenu menu{packet_table};
            for (int column = 0; column < packet_table->model()->columnCount(); ++column) {
                auto* const action = menu.addAction(
                    packet_table->model()->headerData(column, Qt::Horizontal).toString());
                action->setCheckable(true);
                action->setChecked(!packet_table->isColumnHidden(column));
                QObject::connect(action, &QAction::toggled, packet_table, [packet_table, column](bool visible) {
                    packet_table->setColumnHidden(column, !visible);
                });
            }
            menu.exec(packet_table->horizontalHeader()->mapToGlobal(position));
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
            select_byte_range(offset, length, false);
        });

    connect(
        hex_view_,
        &QPlainTextEdit::selectionChanged,
        this,
        [this] {
            if (!displayed_packet_index_.has_value()) {
                return;
            }
            const auto cursor = hex_view_->textCursor();
            const auto text_position = cursor.hasSelection()
                ? cursor.selectionStart()
                : cursor.position();
            const auto byte_offset =
                byte_at_text_position(byte_hex_positions_, text_position);
            if (!byte_offset.has_value()) {
                return;
            }
            current_byte_offset_ = byte_offset;
            offset_spin_->setValue(static_cast<int>(byte_offset.value()));
            update_integer_value(byte_offset.value());
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

    connect(find_next, &QPushButton::clicked, this, [this, search_mode, search_edit] {
        if (!displayed_packet_index_.has_value() || search_edit->text().isEmpty()) {
            return;
        }
        try {
            std::vector<std::uint8_t> pattern;
            if (search_mode->currentIndex() == 0) {
                pattern = packet::parse_hex_pattern(search_edit->text().toStdString());
            } else {
                const auto text_bytes = search_edit->text().toUtf8();
                pattern.assign(text_bytes.begin(), text_bytes.end());
            }
            const auto& bytes = packets_[displayed_packet_index_.value()]->capture.packet.bytes;
            const auto matches = packet::find_bytes(bytes, pattern);
            if (matches.empty()) {
                statusBar()->showMessage(QStringLiteral("No matching bytes"), 3000);
                return;
            }
            const auto next = current_byte_offset_.has_value()
                ? std::upper_bound(
                      matches.begin(), matches.end(), current_byte_offset_.value())
                : matches.begin();
            const auto match = next == matches.end() ? matches.front() : *next;
            select_byte_range(match, pattern.size(), true);
            statusBar()->showMessage(
                QStringLiteral("Match at offset %1").arg(static_cast<qulonglong>(match)),
                3000);
        } catch (const std::invalid_argument& error) {
            statusBar()->showMessage(QString::fromUtf8(error.what()), 3000);
        }
    });
    connect(search_edit, &QLineEdit::returnPressed, find_next, &QPushButton::click);

    connect(go_to, &QPushButton::clicked, this, [this] {
        if (!displayed_packet_index_.has_value()) {
            return;
        }
        const auto offset = static_cast<std::size_t>(offset_spin_->value());
        const auto requested = static_cast<std::size_t>(integer_width_->currentText().toUInt());
        const auto& bytes = packets_[displayed_packet_index_.value()]->capture.packet.bytes;
        const auto available = offset < bytes.size() ? bytes.size() - offset : 0U;
        if (available != 0U) {
            select_byte_range(offset, std::min(requested, available), true);
        }
    });
    connect(
        integer_width_,
        &QComboBox::currentIndexChanged,
        this,
        [this] {
            if (current_byte_offset_.has_value()) {
                update_integer_value(current_byte_offset_.value());
            }
        });
    connect(
        integer_endian_,
        &QComboBox::currentIndexChanged,
        this,
        [this] {
            if (current_byte_offset_.has_value()) {
                update_integer_value(current_byte_offset_.value());
            }
        });

    connect(favorite_filter_action, &QAction::triggered, this, [this, filter_edit] {
        const auto filter = filter_edit->text().trimmed();
        if (filter.isEmpty()) {
            statusBar()->showMessage(QStringLiteral("Enter a capture filter first"), 3000);
            return;
        }
        if (!QCoreApplication::organizationName().isEmpty()) {
            QSettings settings;
            auto favorites = settings.value(QStringLiteral("capture/filterFavorites")).toStringList();
            favorites.removeAll(filter);
            favorites.prepend(filter);
            settings.setValue(QStringLiteral("capture/filterFavorites"), favorites.mid(0, 20));
        }
        auto* const model = qobject_cast<QStringListModel*>(filter_edit->completer()->model());
        if (model != nullptr) {
            auto suggestions = model->stringList();
            suggestions.removeAll(filter);
            suggestions.prepend(filter);
            model->setStringList(suggestions);
        }
        statusBar()->showMessage(QStringLiteral("Capture filter added to favorites"), 3000);
    });

    connect(start_action_, &QAction::triggered, this, [this, interface_list, filter_edit, snap_length] {
        std::vector<std::string> interfaces;
        for (int index = 0; index < interface_list->count(); ++index) {
            const auto* const item = interface_list->item(index);
            if (item->checkState() == Qt::Checked && item->flags().testFlag(Qt::ItemIsEnabled)) {
                interfaces.push_back(item->text().toStdString());
            }
        }
        if (interfaces.empty()) {
            statusBar()->showMessage(QStringLiteral("Select at least one capture interface"), 4000);
            return;
        }

        bool valid_snapshot{false};
        const int snapshot_length = snap_length->currentText().toInt(&valid_snapshot);
        if (!valid_snapshot) {
            statusBar()->showMessage(QStringLiteral("Capture length must be an integer"), 4000);
            return;
        }
        capture::capture_options options;
        options.snapshot_length = snapshot_length;
        options.bpf_filter = filter_edit->text().trimmed().toStdString();

        try {
            latest_capture_time_.reset();
            packet_merger_ = capture::packet_merger{};
            capture_runner_.start(
                interfaces,
                options,
                [this](capture::interface_packet packet) {
                    enqueue_captured_packet(std::move(packet));
                },
                [this](const std::string& message) {
                    QMetaObject::invokeMethod(
                        this,
                        [this, message] {
                            statusBar()->showMessage(
                                QStringLiteral("Capture error: %1")
                                    .arg(QString::fromStdString(message)),
                                8000);
                        },
                        Qt::QueuedConnection);
                });
            start_action_->setEnabled(false);
            pause_action_->setEnabled(true);
            stop_action_->setEnabled(true);
            interface_list->setEnabled(false);
            filter_edit->setEnabled(false);
            snap_length->setEnabled(false);
            statusBar()->showMessage(
                QStringLiteral("Capturing on %1 interface(s)").arg(interfaces.size()));
            const auto used_filter = filter_edit->text().trimmed();
            if (!used_filter.isEmpty()) {
                auto* const model = qobject_cast<QStringListModel*>(
                    filter_edit->completer()->model());
                if (model != nullptr) {
                    auto suggestions = model->stringList();
                    suggestions.removeAll(used_filter);
                    suggestions.prepend(used_filter);
                    model->setStringList(suggestions);
                }
                if (!QCoreApplication::organizationName().isEmpty()) {
                    QSettings settings;
                    auto history = settings.value(
                        QStringLiteral("capture/filterHistory")).toStringList();
                    history.removeAll(used_filter);
                    history.prepend(used_filter);
                    settings.setValue(QStringLiteral("capture/filterHistory"), history.mid(0, 30));
                }
            }
        } catch (const std::exception& error) {
            statusBar()->showMessage(QString::fromUtf8(error.what()), 8000);
        }
    });
    connect(pause_action_, &QAction::triggered, this, [this] {
        if (capture_runner_.paused()) {
            capture_runner_.resume();
            pause_action_->setText(QStringLiteral("Pause"));
            statusBar()->showMessage(QStringLiteral("Capture resumed"));
        } else {
            capture_runner_.pause();
            pause_action_->setText(QStringLiteral("Resume"));
            statusBar()->showMessage(QStringLiteral("Capture paused"));
        }
    });
    connect(stop_action_, &QAction::triggered, this, [this, interface_list, filter_edit, snap_length] {
        stop_capture();
        interface_list->setEnabled(true);
        filter_edit->setEnabled(true);
        snap_length->setEnabled(true);
    });
    connect(open_action, &QAction::triggered, this, [this] {
        const auto path = QFileDialog::getOpenFileName(
            this,
            QStringLiteral("Open packet capture"),
            {},
            QStringLiteral("PCAP files (*.pcap *.cap);;All files (*)"));
        if (path.isEmpty()) {
            return;
        }
        try {
            load_pcap(std::filesystem::path{path.toStdString()});
        } catch (const std::exception& error) {
            statusBar()->showMessage(QString::fromUtf8(error.what()), 8000);
        }
    });
    connect(save_action, &QAction::triggered, this, [this] {
        const auto path = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("Save packet capture"),
            QStringLiteral("capture.pcap"),
            QStringLiteral("PCAP files (*.pcap);;All files (*)"));
        if (path.isEmpty()) {
            return;
        }
        try {
            save_pcap(std::filesystem::path{path.toStdString()});
            statusBar()->showMessage(QStringLiteral("PCAP saved"), 4000);
        } catch (const std::exception& error) {
            statusBar()->showMessage(QString::fromUtf8(error.what()), 8000);
        }
    });
    connect(save_visible_action, &QAction::triggered, this, [this] {
        const auto path = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("Export visible packets"),
            QStringLiteral("visible-packets.pcap"),
            QStringLiteral("PCAP files (*.pcap)"));
        if (path.isEmpty()) {
            return;
        }
        try {
            save_visible_pcap(std::filesystem::path{path.toStdString()});
            statusBar()->showMessage(QStringLiteral("Visible packets exported"), 4000);
        } catch (const std::exception& error) {
            statusBar()->showMessage(QString::fromUtf8(error.what()), 8000);
        }
    });
    connect(export_json_action, &QAction::triggered, this, [this] {
        if (!displayed_packet_index_.has_value()) {
            statusBar()->showMessage(QStringLiteral("Select a packet first"), 4000);
            return;
        }
        const auto path = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("Export protocol analysis"),
            QStringLiteral("packet.json"),
            QStringLiteral("JSON files (*.json)"));
        if (path.isEmpty()) {
            return;
        }
        try {
            export_packet_json(
                displayed_packet_index_.value(),
                std::filesystem::path{path.toStdString()});
            statusBar()->showMessage(QStringLiteral("Protocol JSON exported"), 4000);
        } catch (const std::exception& error) {
            statusBar()->showMessage(QString::fromUtf8(error.what()), 8000);
        }
    });
    connect(
        display_filter_edit_,
        &QLineEdit::returnPressed,
        this,
        &main_window::apply_display_filter);
    connect(
        flow_table_->selectionModel(),
        &QItemSelectionModel::currentRowChanged,
        this,
        [this](const QModelIndex& current) {
            if (!current.isValid()) {
                return;
            }
            const auto id = flow_model_->index(current.row(), 0)
                                .data(Qt::UserRole).toULongLong();
            const auto flows = flow_tracker_.snapshot();
            const auto found = std::find_if(flows.begin(), flows.end(), [id](const auto& flow) {
                return flow.id == id;
            });
            if (found == flows.end()) {
                return;
            }
            flow_data_->setPlainText(
                QStringLiteral("Client → Server (%1 bytes)\n%2\n\nServer → Client (%3 bytes)\n%4")
                    .arg(static_cast<qulonglong>(found->client_to_server_data.size()))
                    .arg(printable_stream(found->client_to_server_data))
                    .arg(static_cast<qulonglong>(found->server_to_client_data.size()))
                    .arg(printable_stream(found->server_to_client_data)));
        });
    connect(
        flow_table_,
        &QTableView::customContextMenuRequested,
        this,
        [this](const QPoint& position) {
            const auto index = flow_table_->indexAt(position);
            if (!index.isValid()) {
                return;
            }
            flow_table_->selectRow(index.row());
            QMenu menu{flow_table_};
            auto* const export_action = menu.addAction(QStringLiteral("Export flow as PCAP…"));
            if (menu.exec(flow_table_->viewport()->mapToGlobal(position)) != export_action) {
                return;
            }
            const auto flow_id = flow_model_->index(index.row(), 0)
                                     .data(Qt::UserRole).toULongLong();
            const auto path = QFileDialog::getSaveFileName(
                this,
                QStringLiteral("Export TCP flow"),
                QStringLiteral("flow-%1.pcap").arg(flow_id),
                QStringLiteral("PCAP files (*.pcap)"));
            if (path.isEmpty()) {
                return;
            }
            try {
                save_flow_pcap(flow_id, std::filesystem::path{path.toStdString()});
                statusBar()->showMessage(QStringLiteral("TCP flow exported"), 4000);
            } catch (const std::exception& error) {
                statusBar()->showMessage(QString::fromUtf8(error.what()), 8000);
            }
        });

    if (!QCoreApplication::organizationName().isEmpty()) {
        QSettings settings;
        restoreGeometry(settings.value(QStringLiteral("ui/geometry")).toByteArray());
        restoreState(settings.value(QStringLiteral("ui/windowState")).toByteArray());
        packet_table->horizontalHeader()->restoreState(
            settings.value(QStringLiteral("ui/packetHeader")).toByteArray());
        filter_edit->setText(settings.value(QStringLiteral("capture/lastFilter")).toString());
        display_filter_edit_->setText(
            settings.value(QStringLiteral("display/lastFilter")).toString());
    }
}

main_window::~main_window() {
    capture_runner_.stop();
    if (!QCoreApplication::organizationName().isEmpty()) {
        QSettings settings;
        settings.setValue(QStringLiteral("ui/geometry"), saveGeometry());
        settings.setValue(QStringLiteral("ui/windowState"), saveState());
        if (const auto* const table = findChild<QTableView*>(QStringLiteral("packetTable"));
            table != nullptr) {
            settings.setValue(
                QStringLiteral("ui/packetHeader"),
                table->horizontalHeader()->saveState());
        }
        if (const auto* const filter = findChild<QLineEdit*>(QStringLiteral("captureFilterEdit"));
            filter != nullptr) {
            settings.setValue(QStringLiteral("capture/lastFilter"), filter->text());
        }
        settings.setValue(QStringLiteral("display/lastFilter"), display_filter_edit_->text());
    }
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
        new address_item{QString::fromStdString(record.source)},
        new QStandardItem{},
        new address_item{QString::fromStdString(record.destination)},
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
    row[3]->setData(QString::fromStdString(record.source), Qt::UserRole + 3);
    row[5]->setData(QString::fromStdString(record.destination), Qt::UserRole + 3);
    packet_model_->appendRow(row);
    if (flow_tracker_.ingest(packets_.back()).has_value()) {
        refresh_flow_view();
    }
    if (const auto datagram = ip_reassembler_.ingest(packets_.back());
        datagram.has_value()) {
        const auto evidence = QStringLiteral(
            "Reassembled %1 bytes from %2 fragments; %3 overlapping byte(s).")
            .arg(static_cast<qulonglong>(datagram->payload.size()))
            .arg(static_cast<qulonglong>(datagram->fragment_count))
            .arg(static_cast<qulonglong>(datagram->overlapping_bytes));
        QList<QStandardItem*> reassembly_row{
            new QStandardItem{QStringLiteral("IP fragment reassembly")},
            new QStandardItem{QStringLiteral("Completed fragmented datagram")},
            new QStandardItem{evidence},
            new QStandardItem{QStringLiteral("Packet %1")
                .arg(static_cast<qulonglong>(record.number))},
        };
        for (auto* const item : reassembly_row) {
            item->setEditable(false);
            item->setBackground(QColor{224, 240, 255});
        }
        anomaly_model_->appendRow(reassembly_row);
    }
    statistics_.ingest(packets_.back());
    refresh_statistics_view();
    auto alerts = anomaly_detector_.ingest(packets_.back());
    const auto flow_alerts = anomaly_detector_.evaluate_flows(flow_tracker_.snapshot());
    alerts.insert(alerts.end(), flow_alerts.begin(), flow_alerts.end());
    for (const auto& alert : alerts) {
        QString related;
        if (alert.packet_number.has_value()) {
            related = QStringLiteral("Packet %1").arg(
                static_cast<qulonglong>(alert.packet_number.value()));
        } else if (alert.flow_id.has_value()) {
            related = QStringLiteral("Flow %1").arg(
                static_cast<qulonglong>(alert.flow_id.value()));
        }
        QList<QStandardItem*> alert_row{
            new QStandardItem{QString::fromStdString(alert.rule)},
            new QStandardItem{QString::fromStdString(alert.title)},
            new QStandardItem{QString::fromStdString(alert.evidence)},
            new QStandardItem{related},
        };
        for (auto* const item : alert_row) {
            item->setEditable(false);
            item->setBackground(QColor{250, 225, 225});
        }
        anomaly_model_->appendRow(alert_row);
    }

    const auto resolve_address = [this, stored_index](
                                     const std::string& address,
                                     const int column) {
        if (address.empty()) {
            return;
        }
        reverse_dns_.resolve(
            address,
            [this, stored_index, column](
                const std::string& raw_address,
                std::optional<std::string> hostname) {
                if (!hostname.has_value() || hostname->empty() ||
                    hostname.value() == raw_address) {
                    return;
                }
                QMetaObject::invokeMethod(
                    this,
                    [this, stored_index, column, raw_address,
                     hostname = std::move(hostname.value())] {
                        for (int model_row = 0; model_row < packet_model_->rowCount();
                             ++model_row) {
                            auto* const number_item = packet_model_->item(model_row, 0);
                            if (number_item == nullptr ||
                                number_item->data(Qt::UserRole).toULongLong() !=
                                    stored_index) {
                                continue;
                            }
                            auto* const address_item = packet_model_->item(model_row, column);
                            address_item->setText(
                                QStringLiteral("%1 (%2)")
                                    .arg(QString::fromStdString(hostname))
                                    .arg(QString::fromStdString(raw_address)));
                            break;
                        }
                    },
                    Qt::QueuedConnection);
            });
    };
    resolve_address(record.source, 3);
    resolve_address(record.destination, 5);
    if (display_filter_.has_value()) {
        apply_display_filter();
    }
}

void main_window::load_pcap(const std::filesystem::path& path) {
    if (capture_runner_.running()) {
        stop_capture();
    }
    auto contents = capture::read_pcap_file(path);
    if (contents.link_type != 1) {
        throw capture::pcap_error{
            "unsupported PCAP link type " + std::to_string(contents.link_type) +
            "; NetScope currently requires Ethernet"};
    }

    repository_.clear();
    flow_tracker_.clear();
    statistics_.clear();
    anomaly_detector_.clear();
    ip_reassembler_.clear();
    annotations_.clear();
    flow_model_->removeRows(0, flow_model_->rowCount());
    flow_data_->clear();
    anomaly_model_->removeRows(0, anomaly_model_->rowCount());
    refresh_statistics_view();
    packet_model_->removeRows(0, packet_model_->rowCount());
    packets_.clear();
    protocol_tree_->clear();
    hex_view_->clear();
    byte_hex_positions_.clear();
    displayed_packet_index_.reset();
    current_byte_offset_.reset();
    current_snapshot_length_ = contents.snapshot_length;

    for (auto& packet : contents.packets) {
        append_packet(repository_.append(capture::merged_packet{
            std::move(packet),
            {"pcap"},
        }));
    }
    setWindowTitle(
        QStringLiteral("NetScope — %1").arg(QString::fromStdString(path.filename().string())));
    statusBar()->showMessage(
        QStringLiteral("Loaded %1 packet(s)")
            .arg(static_cast<qulonglong>(packets_.size())),
        4000);
}

void main_window::save_pcap(const std::filesystem::path& path) const {
    std::vector<capture::captured_packet> packets;
    packets.reserve(packets_.size());
    for (const auto& record : packets_) {
        packets.push_back(record->capture.packet);
    }
    capture::write_pcap_file(path, 1, current_snapshot_length_, packets);
}

void main_window::save_visible_pcap(const std::filesystem::path& path) const {
    const auto* const table = findChild<QTableView*>(QStringLiteral("packetTable"));
    if (table == nullptr) {
        throw std::runtime_error{"packet table is unavailable"};
    }
    std::vector<capture::captured_packet> visible;
    for (int row = 0; row < packet_model_->rowCount(); ++row) {
        if (table->isRowHidden(row)) {
            continue;
        }
        const auto index = static_cast<std::size_t>(
            packet_model_->index(row, 0).data(Qt::UserRole).toULongLong());
        if (index < packets_.size()) {
            visible.push_back(packets_[index]->capture.packet);
        }
    }
    capture::write_pcap_file(path, 1, current_snapshot_length_, visible);
}

void main_window::save_flow_pcap(
    const std::uint64_t flow_id,
    const std::filesystem::path& path) const {
    const auto flows = flow_tracker_.snapshot();
    const auto flow = std::find_if(flows.begin(), flows.end(), [flow_id](const auto& item) {
        return item.id == flow_id;
    });
    if (flow == flows.end()) {
        throw std::out_of_range{"TCP flow does not exist"};
    }
    std::vector<capture::captured_packet> output;
    for (const auto number : flow->packet_numbers) {
        const auto packet = std::find_if(packets_.begin(), packets_.end(), [number](const auto& item) {
            return item->number == number;
        });
        if (packet != packets_.end()) {
            output.push_back((*packet)->capture.packet);
        }
    }
    capture::write_pcap_file(path, 1, current_snapshot_length_, output);
}

void main_window::export_packet_json(
    const std::size_t packet_index,
    const std::filesystem::path& path) const {
    if (packet_index >= packets_.size()) {
        throw std::out_of_range{"packet export index is out of range"};
    }
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    if (!output) {
        throw std::runtime_error{"unable to open JSON export file"};
    }
    output << protocol::to_json(packets_[packet_index]->analysis) << '\n';
    if (!output) {
        throw std::runtime_error{"unable to write JSON export file"};
    }
}

void main_window::set_packet_annotation(
    const std::size_t packet_index,
    const bool marked,
    std::string note) {
    if (packet_index >= packets_.size()) {
        throw std::out_of_range{"packet annotation index is out of range"};
    }
    const auto tooltip = QString::fromStdString(note);
    if (!marked && note.empty()) {
        annotations_.erase(packet_index);
    } else {
        annotations_[packet_index] = packet_annotation{marked, std::move(note)};
    }

    for (int row = 0; row < packet_model_->rowCount(); ++row) {
        auto* const number_item = packet_model_->item(row, 0);
        if (number_item == nullptr ||
            static_cast<std::size_t>(number_item->data(Qt::UserRole).toULongLong()) !=
                packet_index) {
            continue;
        }
        const auto& record = *packets_[packet_index];
        number_item->setText(
            marked
                ? QStringLiteral("★ %1").arg(static_cast<qulonglong>(record.number))
                : QString::number(record.number));
        const QBrush background{
            marked ? QColor{255, 244, 179} : protocol_color(record.protocol)};
        for (int column = 0; column < packet_model_->columnCount(); ++column) {
            auto* const item = packet_model_->item(row, column);
            item->setBackground(background);
            item->setData(tooltip, Qt::ToolTipRole);
        }
        return;
    }
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
    current_byte_offset_.reset();
    offset_spin_->setRange(
        0,
        record.capture.packet.bytes.empty()
            ? 0
            : static_cast<int>(record.capture.packet.bytes.size() - 1U));
    integer_value_->setText(QStringLiteral("No byte selected"));
}

void main_window::select_byte_range(
    const std::size_t offset,
    const std::size_t length,
    const bool notify) {
    if (length == 0U || offset >= byte_hex_positions_.size() ||
        length > byte_hex_positions_.size() - offset) {
        return;
    }
    std::optional<QSignalBlocker> blocker;
    if (!notify) {
        blocker.emplace(hex_view_);
    }
    QTextCursor cursor{hex_view_->document()};
    cursor.setPosition(byte_hex_positions_[offset]);
    cursor.setPosition(
        byte_hex_positions_[offset + length - 1U] + 2,
        QTextCursor::KeepAnchor);
    hex_view_->setTextCursor(cursor);
    hex_view_->ensureCursorVisible();
    current_byte_offset_ = offset;
    offset_spin_->setValue(static_cast<int>(offset));
    update_integer_value(offset);
}

void main_window::update_integer_value(const std::size_t offset) {
    if (!displayed_packet_index_.has_value()) {
        return;
    }
    const auto width = static_cast<std::size_t>(integer_width_->currentText().toUInt());
    const auto order = integer_endian_->currentIndex() == 0
        ? packet::byte_order::big_endian
        : packet::byte_order::little_endian;
    try {
        const auto value = packet::interpret_unsigned(
            packets_[displayed_packet_index_.value()]->capture.packet.bytes,
            offset,
            width,
            order);
        integer_value_->setText(
            QStringLiteral("%1 (0x%2)")
                .arg(static_cast<qulonglong>(value))
                .arg(
                    static_cast<qulonglong>(value),
                    static_cast<int>(width * 2U),
                    16,
                    QLatin1Char('0')));
    } catch (const std::out_of_range&) {
        integer_value_->setText(QStringLiteral("Not enough bytes"));
    }
}

void main_window::enqueue_captured_packet(capture::interface_packet packet) {
    bool schedule{false};
    {
        const std::lock_guard lock{captured_mutex_};
        captured_pending_.push_back(std::move(packet));
        if (!drain_scheduled_.exchange(true)) {
            schedule = true;
        }
    }
    if (schedule) {
        QMetaObject::invokeMethod(
            this,
            [this] { drain_captured_packets(false); },
            Qt::QueuedConnection);
    }
}

void main_window::drain_captured_packets(const bool flush_all) {
    std::vector<capture::interface_packet> pending;
    {
        const std::lock_guard lock{captured_mutex_};
        pending.swap(captured_pending_);
        drain_scheduled_.store(false);
    }
    for (auto& packet : pending) {
        if (!latest_capture_time_.has_value() ||
            packet.packet.timestamp > latest_capture_time_.value()) {
            latest_capture_time_ = packet.packet.timestamp;
        }
        packet_merger_.push(std::move(packet));
    }

    std::vector<capture::merged_packet> ready;
    if (flush_all) {
        ready = packet_merger_.flush_all();
    } else if (latest_capture_time_.has_value()) {
        ready = packet_merger_.drain_ready(latest_capture_time_.value());
    }
    for (auto& packet : ready) {
        append_packet(repository_.append(std::move(packet)));
    }
    if (!flush_all && packet_merger_.pending_count() != 0U &&
        !merge_flush_scheduled_) {
        merge_flush_scheduled_ = true;
        QTimer::singleShot(std::chrono::milliseconds{5}, this, [this] {
            merge_flush_scheduled_ = false;
            drain_captured_packets(true);
        });
    }
}

void main_window::stop_capture() {
    capture_runner_.stop();
    drain_captured_packets(true);
    start_action_->setEnabled(true);
    pause_action_->setEnabled(false);
    pause_action_->setText(QStringLiteral("Pause"));
    stop_action_->setEnabled(false);
    statusBar()->showMessage(
        QStringLiteral("Capture stopped — %1 packet(s)")
            .arg(static_cast<qulonglong>(repository_.size())));
}

void main_window::apply_display_filter() {
    try {
        display_filter_.emplace(display_filter_edit_->text().trimmed().toStdString());
        display_filter_edit_->setStyleSheet({});
        display_filter_edit_->setToolTip({});
    } catch (const analysis::filter_error& error) {
        display_filter_edit_->setStyleSheet(QStringLiteral("QLineEdit { border: 1px solid #c94b4b; }"));
        display_filter_edit_->setToolTip(
            QStringLiteral("Position %1: %2")
                .arg(static_cast<qulonglong>(error.position()))
                .arg(QString::fromUtf8(error.what())));
        statusBar()->showMessage(display_filter_edit_->toolTip(), 6000);
        return;
    }

    auto* const table = qobject_cast<QTableView*>(packet_model_->parent());
    std::size_t visible{0U};
    for (int row = 0; row < packet_model_->rowCount(); ++row) {
        const auto stored_index = static_cast<std::size_t>(
            packet_model_->index(row, 0).data(Qt::UserRole).toULongLong());
        const bool matches = stored_index < packets_.size() &&
            display_filter_->matches(*packets_[stored_index]);
        table->setRowHidden(row, !matches);
        if (matches) {
            ++visible;
        }
    }
    statusBar()->showMessage(
        QStringLiteral("Display filter: %1 of %2 packet(s)")
            .arg(static_cast<qulonglong>(visible))
            .arg(static_cast<qulonglong>(packets_.size())),
        4000);
}

void main_window::refresh_flow_view() {
    const bool sorting = flow_table_->isSortingEnabled();
    flow_table_->setSortingEnabled(false);
    flow_model_->removeRows(0, flow_model_->rowCount());
    for (const auto& flow : flow_tracker_.snapshot()) {
        const auto rtt = flow.round_trip_time.has_value()
            ? QStringLiteral("%1 ms").arg(
                  static_cast<double>(flow.round_trip_time->count()) / 1000.0,
                  0,
                  'f',
                  3)
            : QStringLiteral("—");
        QList<QStandardItem*> row{
            new QStandardItem{QString::number(flow.id)},
            new QStandardItem{endpoint_text(flow.client)},
            new QStandardItem{endpoint_text(flow.server)},
            new QStandardItem{flow_state_name(flow.state)},
            new QStandardItem{QString::number(flow.packet_count)},
            new QStandardItem{QString::number(flow.byte_count)},
            new QStandardItem{rtt},
            new QStandardItem{QString::number(flow.retransmissions)},
            new QStandardItem{QString::number(flow.out_of_order_segments)},
        };
        for (auto* const item : row) {
            item->setEditable(false);
            item->setData(static_cast<qulonglong>(flow.id), Qt::UserRole);
        }
        flow_model_->appendRow(row);
    }
    flow_table_->setSortingEnabled(sorting);
}

void main_window::refresh_statistics_view() {
    const auto snapshot = statistics_.snapshot();
    statistics_packet_count_->setText(
        QStringLiteral("Packets: %1").arg(static_cast<qulonglong>(snapshot.total_packets)));
    statistics_byte_count_->setText(
        QStringLiteral("Bytes: %1").arg(static_cast<qulonglong>(snapshot.total_bytes)));
    statistics_rate_->setText(
        QStringLiteral("Rate: %1 packets/s, %2 B/s")
            .arg(snapshot.packet_rate, 0, 'f', 1)
            .arg(snapshot.byte_rate, 0, 'f', 1));
    protocol_series_->clear();
    for (const auto& [protocol, count] : snapshot.protocol_counts) {
        protocol_series_->append(
            QStringLiteral("%1 (%2)")
                .arg(QString::fromStdString(protocol))
                .arg(static_cast<qulonglong>(count)),
            static_cast<qreal>(count));
    }

    std::vector<std::pair<std::string, std::uint64_t>> hosts{
        snapshot.host_counts.begin(), snapshot.host_counts.end()};
    std::sort(hosts.begin(), hosts.end(), [](const auto& left, const auto& right) {
        return left.second > right.second;
    });
    QString summary{QStringLiteral("Top hosts\n")};
    for (std::size_t index = 0U; index < std::min(hosts.size(), std::size_t{5U}); ++index) {
        summary += QStringLiteral("%1  %2\n")
            .arg(QString::fromStdString(hosts[index].first))
            .arg(static_cast<qulonglong>(hosts[index].second));
    }
    summary += QStringLiteral("\nTop ports\n");
    std::vector<std::pair<std::uint16_t, std::uint64_t>> ports{
        snapshot.port_counts.begin(), snapshot.port_counts.end()};
    std::sort(ports.begin(), ports.end(), [](const auto& left, const auto& right) {
        return left.second > right.second;
    });
    for (std::size_t index = 0U; index < std::min(ports.size(), std::size_t{5U}); ++index) {
        summary += QStringLiteral("%1  %2\n")
            .arg(ports[index].first)
            .arg(static_cast<qulonglong>(ports[index].second));
    }
    statistics_top_->setPlainText(summary);
}

}  // namespace netscope::ui

