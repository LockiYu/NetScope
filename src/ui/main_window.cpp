#include "netscope/ui/main_window.h"

#include "netscope/capture/live_capture.h"

#include <QAction>
#include <QComboBox>
#include <QDockWidget>
#include <QFontDatabase>
#include <QFormLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QStandardItemModel>
#include <QStatusBar>
#include <QTableView>
#include <QToolBar>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QWidget>

#include <exception>

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
    auto* const packet_model = new QStandardItemModel{packet_table};
    packet_model->setHorizontalHeaderLabels({
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
    packet_table->setModel(packet_model);
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
    auto* const protocol_tree = new QTreeWidget{details};
    protocol_tree->setObjectName(QStringLiteral("protocolTree"));
    protocol_tree->setColumnCount(2);
    protocol_tree->setHeaderLabels({QStringLiteral("Field"), QStringLiteral("Value")});
    protocol_tree->setAlternatingRowColors(true);
    protocol_tree->header()->setStretchLastSection(true);

    auto* const hex_view = new QPlainTextEdit{details};
    hex_view->setObjectName(QStringLiteral("hexView"));
    hex_view->setReadOnly(true);
    hex_view->setLineWrapMode(QPlainTextEdit::NoWrap);
    hex_view->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    hex_view->setPlaceholderText(QStringLiteral(
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
}

}  // namespace netscope::ui

