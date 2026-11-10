cmake_minimum_required(VERSION 3.25)

project(ex1a_sniffer VERSION 0.1.0 LANGUAGES CXX)

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

if(NETSCOPE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

