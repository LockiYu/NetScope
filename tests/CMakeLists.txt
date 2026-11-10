find_package(GTest CONFIG REQUIRED)

include(GoogleTest)

add_executable(netscope_toolchain_test
    unit/build_info_test.cpp
)

target_include_directories(netscope_toolchain_test PRIVATE
    "${PROJECT_SOURCE_DIR}/include"
)

target_link_libraries(netscope_toolchain_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_toolchain_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_main_window_test
    integration/main_window_test.cpp
)

target_include_directories(netscope_main_window_test PRIVATE
    "${PROJECT_SOURCE_DIR}/include"
)

target_link_libraries(netscope_main_window_test PRIVATE
    netscope_ui
    GTest::gtest
)

gtest_discover_tests(netscope_main_window_test
    DISCOVERY_MODE PRE_TEST
    PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
)


