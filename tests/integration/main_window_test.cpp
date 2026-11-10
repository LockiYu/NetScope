#include "netscope/ui/main_window.h"

#include <QApplication>

#include <gtest/gtest.h>

TEST(main_window_test, provides_a_ready_application_shell) {
    netscope::ui::main_window window;

    EXPECT_EQ(window.windowTitle(), QStringLiteral("NetScope"));
    EXPECT_NE(window.centralWidget(), nullptr);
    EXPECT_GE(window.minimumWidth(), 960);
    EXPECT_GE(window.minimumHeight(), 640);
}

int main(int argc, char** argv) {
    QApplication application{argc, argv};
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

