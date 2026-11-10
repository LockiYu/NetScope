#include "netscope/capture/pcap_file.h"

#include <QTemporaryDir>

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

namespace {

using netscope::capture::captured_packet;
using netscope::capture::pcap_error;
using netscope::capture::read_pcap_file;
using netscope::capture::write_pcap_file;

const std::vector<std::uint8_t> ethernet_header{
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
};

void write_bytes(
    const std::filesystem::path& path,
    const std::vector<std::uint8_t>& bytes) {
    std::ofstream output{path, std::ios::binary};
    ASSERT_TRUE(output.good());
    output.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
}

TEST(pcap_file_test, reads_standard_little_endian_capture) {
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const auto path = std::filesystem::path{directory.path().toStdString()} / "sample.pcap";
    std::vector<std::uint8_t> file{
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
        0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
        1, 0, 0, 0, 2, 0, 0, 0, 14, 0, 0, 0, 14, 0, 0, 0,
    };
    file.insert(file.end(), ethernet_header.begin(), ethernet_header.end());
    write_bytes(path, file);

    const auto contents = read_pcap_file(path);

    EXPECT_EQ(contents.link_type, 1);
    EXPECT_EQ(contents.snapshot_length, 65535);
    ASSERT_EQ(contents.packets.size(), 1U);
    EXPECT_EQ(contents.packets.front().captured_length, 14U);
    EXPECT_EQ(contents.packets.front().original_length, 14U);
    EXPECT_EQ(contents.packets.front().bytes, ethernet_header);
    EXPECT_EQ(
        std::chrono::duration_cast<std::chrono::microseconds>(
            contents.packets.front().timestamp.time_since_epoch()).count(),
        1000002);
}

TEST(pcap_file_test, writes_capture_that_can_be_read_back) {
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const auto path = std::filesystem::path{directory.path().toStdString()} / "roundtrip.pcap";
    const captured_packet packet{
        std::chrono::system_clock::time_point{std::chrono::microseconds{2000003}},
        14U,
        20U,
        ethernet_header,
    };

    write_pcap_file(path, 1, 65535, {packet});
    const auto contents = read_pcap_file(path);

    ASSERT_EQ(contents.packets.size(), 1U);
    EXPECT_EQ(contents.packets.front().original_length, 20U);
    EXPECT_EQ(contents.packets.front().bytes, ethernet_header);
}

TEST(pcap_file_test, rejects_corrupt_input) {
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const auto path = std::filesystem::path{directory.path().toStdString()} / "broken.pcap";
    write_bytes(path, {0x00, 0x01, 0x02});

    EXPECT_THROW(static_cast<void>(read_pcap_file(path)), pcap_error);
}

}  // namespace

