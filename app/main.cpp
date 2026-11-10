#include "netscope/ui/main_window.h"

#include <QApplication>

int main(int argc, char** argv) {
    QApplication application{argc, argv};
    QApplication::setApplicationName(QStringLiteral("NetScope"));
    QApplication::setOrganizationName(QStringLiteral("UCAS"));

    netscope::ui::main_window window;
    window.show();

    return application.exec();
}

