#include "netscope/ui/main_window.h"

#include <QLabel>
#include <QVBoxLayout>
#include <QWidget>

namespace netscope::ui {

main_window::main_window(QWidget* parent) : QMainWindow{parent} {
    setWindowTitle(QStringLiteral("NetScope"));
    setMinimumSize(960, 640);

    auto* const workspace = new QWidget{this};
    auto* const layout = new QVBoxLayout{workspace};
    auto* const placeholder = new QLabel{
        QStringLiteral("Packet capture workspace"), workspace};

    placeholder->setAlignment(Qt::AlignCenter);
    layout->addWidget(placeholder);
    setCentralWidget(workspace);
}

}  // namespace netscope::ui

