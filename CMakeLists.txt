cmake_minimum_required(VERSION 3.25)

project(ex1a_sniffer VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(NETSCOPE_BUILD_TESTS "Build NetScope tests" ON)
option(NETSCOPE_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(NETSCOPE_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(NETSCOPE_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(NETSCOPE_ENABLE_COVERAGE "Enable Clang source coverage" OFF)

if(NETSCOPE_ENABLE_ASAN AND NETSCOPE_ENABLE_TSAN)
    message(FATAL_ERROR "ASan and TSan cannot be enabled together")
endif()

find_package(Qt6 6.8 REQUIRED COMPONENTS Core Widgets Charts)

find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h REQUIRED)
find_library(PCAP_LIBRARY NAMES pcap REQUIRED)

add_library(PCAP::PCAP UNKNOWN IMPORTED)
set_target_properties(PCAP::PCAP PROPERTIES
    IMPORTED_LOCATION "${PCAP_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
)

add_library(netscope_project_options INTERFACE)
target_compile_options(netscope_project_options INTERFACE
    $<$<CXX_COMPILER_ID:AppleClang,Clang>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wsign-conversion>
)

if(NETSCOPE_ENABLE_ASAN)
    target_compile_options(netscope_project_options INTERFACE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(netscope_project_options INTERFACE -fsanitize=address)
endif()

if(NETSCOPE_ENABLE_UBSAN)
    target_compile_options(netscope_project_options INTERFACE -fsanitize=undefined -fno-omit-frame-pointer)
    target_link_options(netscope_project_options INTERFACE -fsanitize=undefined)
endif()

if(NETSCOPE_ENABLE_TSAN)
    target_compile_options(netscope_project_options INTERFACE -fsanitize=thread -fno-omit-frame-pointer)
    target_link_options(netscope_project_options INTERFACE -fsanitize=thread)
endif()

if(NETSCOPE_ENABLE_COVERAGE)
    target_compile_options(netscope_project_options INTERFACE -fprofile-instr-generate -fcoverage-mapping)
    target_link_options(netscope_project_options INTERFACE -fprofile-instr-generate)
endif()

add_library(netscope_core STATIC
    src/build_info.cpp
    src/analysis/display_filter.cpp
    src/analysis/reverse_dns.cpp
    src/analysis/tcp_flow.cpp
    src/analysis/traffic_statistics.cpp
    src/capture/capture_runner.cpp
    src/capture/live_capture.cpp
    src/capture/packet_merger.cpp
    src/capture/pcap_file.cpp
    src/packet/byte_inspector.cpp
    src/packet/byte_reader.cpp
    src/packet/packet_repository.cpp
    src/protocol/checksum.cpp
    src/protocol/application_parser.cpp
    src/protocol/packet_parser.cpp
    src/protocol/protocol_model.cpp
)

target_include_directories(netscope_core PUBLIC
    "${PROJECT_SOURCE_DIR}/include"
)

target_link_libraries(netscope_core PUBLIC
    netscope_project_options
    PCAP::PCAP
    Qt6::Core
)

add_library(netscope_ui STATIC
    src/ui/main_window.cpp
)

target_include_directories(netscope_ui PUBLIC
    "${PROJECT_SOURCE_DIR}/include"
)

target_link_libraries(netscope_ui PUBLIC
    netscope_project_options
    netscope_core
    Qt6::Widgets
    Qt6::Charts
)

qt_add_executable(netscope_app MACOSX_BUNDLE
    app/main.cpp
)

target_link_libraries(netscope_app PRIVATE netscope_ui)

set_target_properties(netscope_app PROPERTIES
    OUTPUT_NAME "NetScope"
    MACOSX_BUNDLE_BUNDLE_NAME "NetScope"
    MACOSX_BUNDLE_GUI_IDENTIFIER "edu.ucas.netscope"
    MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
)

if(NETSCOPE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

