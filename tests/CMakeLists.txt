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

