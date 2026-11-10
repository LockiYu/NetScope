#pragma once

#include <QMainWindow>

namespace netscope::ui {

class main_window final : public QMainWindow {
public:
    explicit main_window(QWidget* parent = nullptr);
};

}  // namespace netscope::ui

