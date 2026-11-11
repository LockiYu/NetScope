find_package(GTest CONFIG REQUIRED)

include(GoogleTest)

set(NETSCOPE_TEST_SUPPORT_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/support/asan_options.cpp"
)

add_executable(netscope_toolchain_test
    unit/build_info_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
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
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
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

add_executable(netscope_byte_reader_test
    unit/byte_reader_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_byte_reader_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_byte_reader_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_protocol_model_test
    unit/protocol_model_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_protocol_model_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_protocol_model_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_network_parser_test
    unit/network_parser_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_network_parser_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_network_parser_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_checksum_test
    unit/checksum_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_checksum_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_checksum_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_pcap_file_test
    unit/pcap_file_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_pcap_file_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_pcap_file_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_live_capture_test
    unit/live_capture_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_live_capture_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_live_capture_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_packet_merger_test
    unit/packet_merger_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_packet_merger_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_packet_merger_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_packet_repository_test
    unit/packet_repository_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_packet_repository_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_packet_repository_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_byte_inspector_test
    unit/byte_inspector_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_byte_inspector_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_byte_inspector_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_capture_runner_test
    unit/capture_runner_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_capture_runner_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_capture_runner_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_display_filter_test
    unit/display_filter_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_display_filter_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_display_filter_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_application_parser_test
    unit/application_parser_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_application_parser_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_application_parser_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_reverse_dns_test
    unit/reverse_dns_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_reverse_dns_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_reverse_dns_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_tcp_flow_test
    unit/tcp_flow_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_tcp_flow_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_tcp_flow_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_traffic_statistics_test
    unit/traffic_statistics_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_traffic_statistics_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_traffic_statistics_test DISCOVERY_MODE PRE_TEST)

add_executable(netscope_anomaly_detector_test
    unit/anomaly_detector_test.cpp
    ${NETSCOPE_TEST_SUPPORT_SOURCE}
)

target_link_libraries(netscope_anomaly_detector_test PRIVATE
    netscope_core
    GTest::gtest_main
)

gtest_discover_tests(netscope_anomaly_detector_test DISCOVERY_MODE PRE_TEST)









