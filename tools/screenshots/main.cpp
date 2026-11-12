// Renders the NetScope interface to PNG files for the experiment report.
//
// The tool runs without a capture device: it feeds deterministic synthetic
// frames through the public window API, using an injected process snapshot and
// a no-op reverse DNS resolver, so the screenshots are reproducible.
#include "netscope/ui/main_window.h"

#include "netscope/capture/capture_runner.h"
#include "netscope/packet/packet_repository.h"

#include <QApplication>
#include <QtCharts/QChart>
#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>
#include <QComboBox>
#include <QDockWidget>
#include <QLineEdit>
#include <QMetaObject>
#include <QTableView>
#include <QWidget>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using bytes = std::vector<std::uint8_t>;

constexpr std::array<std::uint8_t, 6> host_mac{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a};
constexpr std::array<std::uint8_t, 6> gateway_mac{0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
constexpr std::array<std::uint8_t, 4> host_ip{192, 168, 1, 10};

std::uint16_t checksum(const bytes& data) {
    std::uint32_t sum{0};
    for (std::size_t index = 0; index + 1U < data.size(); index += 2U) {
        sum += static_cast<std::uint32_t>(data[index]) << 8U;
        sum += data[index + 1U];
    }
    if (data.size() % 2U != 0U) {
        sum += static_cast<std::uint32_t>(data.back()) << 8U;
    }
    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xffffU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum);
}

void append16(bytes& output, const std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void append32(bytes& output, const std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

bytes ethernet(const std::array<std::uint8_t, 6>& destination, const std::uint16_t type) {
    bytes frame(destination.begin(), destination.end());
    frame.insert(frame.end(), host_mac.begin(), host_mac.end());
    append16(frame, type);
    return frame;
}

bytes ipv4(
    const std::array<std::uint8_t, 4>& source,
    const std::array<std::uint8_t, 4>& destination,
    const std::uint8_t protocol,
    const bytes& payload) {
    bytes header{0x45, 0x00};
    append16(header, static_cast<std::uint16_t>(20U + payload.size()));
    append16(header, 0x1b3cU);
    append16(header, 0x4000U);
    header.push_back(64U);
    header.push_back(protocol);
    append16(header, 0U);
    header.insert(header.end(), source.begin(), source.end());
    header.insert(header.end(), destination.begin(), destination.end());
    const auto header_checksum = checksum(header);
    header[10] = static_cast<std::uint8_t>(header_checksum >> 8U);
    header[11] = static_cast<std::uint8_t>(header_checksum);
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}

bytes tcp_segment(
    const std::uint16_t source_port,
    const std::uint16_t destination_port,
    const std::uint32_t sequence,
    const std::uint32_t acknowledgement,
    const std::uint8_t flags,
    const bytes& payload,
    const std::array<std::uint8_t, 4>& source,
    const std::array<std::uint8_t, 4>& destination) {
    bytes segment;
    append16(segment, source_port);
    append16(segment, destination_port);
    append32(segment, sequence);
    append32(segment, acknowledgement);
    segment.push_back(0x50U);
    segment.push_back(flags);
    append16(segment, 65535U);
    append16(segment, 0U);
    append16(segment, 0U);
    segment.insert(segment.end(), payload.begin(), payload.end());

    bytes pseudo;
    pseudo.insert(pseudo.end(), source.begin(), source.end());
    pseudo.insert(pseudo.end(), destination.begin(), destination.end());
    pseudo.push_back(0U);
    pseudo.push_back(6U);
    append16(pseudo, static_cast<std::uint16_t>(segment.size()));
    pseudo.insert(pseudo.end(), segment.begin(), segment.end());
    const auto segment_checksum = checksum(pseudo);
    segment[16] = static_cast<std::uint8_t>(segment_checksum >> 8U);
    segment[17] = static_cast<std::uint8_t>(segment_checksum);
    return segment;
}

bytes udp_datagram(
    const std::uint16_t source_port,
    const std::uint16_t destination_port,
    const bytes& payload,
    const std::array<std::uint8_t, 4>& source,
    const std::array<std::uint8_t, 4>& destination) {
    bytes datagram;
    append16(datagram, source_port);
    append16(datagram, destination_port);
    append16(datagram, static_cast<std::uint16_t>(8U + payload.size()));
    append16(datagram, 0U);
    datagram.insert(datagram.end(), payload.begin(), payload.end());

    bytes pseudo;
    pseudo.insert(pseudo.end(), source.begin(), source.end());
    pseudo.insert(pseudo.end(), destination.begin(), destination.end());
    pseudo.push_back(0U);
    pseudo.push_back(17U);
    append16(pseudo, static_cast<std::uint16_t>(datagram.size()));
    pseudo.insert(pseudo.end(), datagram.begin(), datagram.end());
    const auto datagram_checksum = checksum(pseudo);
    datagram[6] = static_cast<std::uint8_t>(datagram_checksum >> 8U);
    datagram[7] = static_cast<std::uint8_t>(datagram_checksum);
    return datagram;
}

bytes icmp_echo(const std::uint16_t identifier, const std::uint16_t sequence) {
    bytes message{8U, 0U, 0U, 0U};
    append16(message, identifier);
    append16(message, sequence);
    message.insert(message.end(), {'n', 'e', 't', 's', 'c', 'o', 'p', 'e'});
    const auto message_checksum = checksum(message);
    message[2] = static_cast<std::uint8_t>(message_checksum >> 8U);
    message[3] = static_cast<std::uint8_t>(message_checksum);
    return message;
}

bytes dns_query() {
    bytes query{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    for (const std::string text : {"www", "example", "com"}) {
        query.push_back(static_cast<std::uint8_t>(text.size()));
        query.insert(query.end(), text.begin(), text.end());
    }
    query.push_back(0U);
    append16(query, 1U);
    append16(query, 1U);
    return query;
}

bytes dns_response() {
    bytes response = dns_query();
    response[2] = 0x81U;
    response[3] = 0x80U;
    response[6] = 0x00U;
    response[7] = 0x01U;
    response.insert(response.end(), {0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04});
    response.insert(response.end(), {93, 184, 216, 34});
    return response;
}

bytes tls_client_hello(const std::string& hostname) {
    const std::string alpn{"h2"};
    bytes sni;                                   // server_name extension body
    append16(sni, static_cast<std::uint16_t>(3U + hostname.size()));
    sni.push_back(0U);
    append16(sni, static_cast<std::uint16_t>(hostname.size()));
    sni.insert(sni.end(), hostname.begin(), hostname.end());

    bytes alpn_body;
    append16(alpn_body, static_cast<std::uint16_t>(1U + alpn.size()));
    alpn_body.push_back(static_cast<std::uint8_t>(alpn.size()));
    alpn_body.insert(alpn_body.end(), alpn.begin(), alpn.end());

    bytes extensions;
    append16(extensions, 0U);
    append16(extensions, static_cast<std::uint16_t>(sni.size()));
    extensions.insert(extensions.end(), sni.begin(), sni.end());
    append16(extensions, 16U);
    append16(extensions, static_cast<std::uint16_t>(alpn_body.size()));
    extensions.insert(extensions.end(), alpn_body.begin(), alpn_body.end());

    bytes handshake{0x03, 0x03};
    for (std::uint8_t index = 0U; index < 32U; ++index) {
        handshake.push_back(static_cast<std::uint8_t>(index * 7U + 3U));
    }
    handshake.push_back(0U);                     // session id length
    append16(handshake, 2U);
    append16(handshake, 0x1301U);
    handshake.push_back(1U);
    handshake.push_back(0U);
    append16(handshake, static_cast<std::uint16_t>(extensions.size()));
    handshake.insert(handshake.end(), extensions.begin(), extensions.end());

    bytes record{0x01};
    const auto handshake_length = static_cast<std::uint32_t>(handshake.size());
    record.push_back(static_cast<std::uint8_t>(handshake_length >> 16U));
    record.push_back(static_cast<std::uint8_t>(handshake_length >> 8U));
    record.push_back(static_cast<std::uint8_t>(handshake_length));
    record.insert(record.end(), handshake.begin(), handshake.end());

    bytes hello{0x16, 0x03, 0x01};
    append16(hello, static_cast<std::uint16_t>(record.size()));
    hello.insert(hello.end(), record.begin(), record.end());
    return hello;
}

bytes as_bytes(const std::string& text) {
    return bytes{text.begin(), text.end()};
}

bytes ip_frame(
    const std::array<std::uint8_t, 4>& source,
    const std::array<std::uint8_t, 4>& destination,
    const std::uint8_t protocol,
    const bytes& ip_payload) {
    auto frame = ethernet(gateway_mac, 0x0800U);
    const auto header = ipv4(source, destination, protocol, ip_payload);
    frame.insert(frame.end(), header.begin(), header.end());
    return frame;
}

bytes tcp_frame(
    const std::array<std::uint8_t, 4>& source,
    const std::uint16_t source_port,
    const std::array<std::uint8_t, 4>& destination,
    const std::uint16_t destination_port,
    const std::uint32_t sequence,
    const std::uint32_t acknowledgement,
    const std::uint8_t flags,
    const bytes& payload = {}) {
    auto frame = ethernet(gateway_mac, 0x0800U);
    const auto header = ipv4(
        source,
        destination,
        6U,
        tcp_segment(
            source_port,
            destination_port,
            sequence,
            acknowledgement,
            flags,
            payload,
            source,
            destination));
    frame.insert(frame.end(), header.begin(), header.end());
    return frame;
}

bytes udp_frame(
    const std::array<std::uint8_t, 4>& source,
    const std::uint16_t source_port,
    const std::array<std::uint8_t, 4>& destination,
    const std::uint16_t destination_port,
    const bytes& payload) {
    auto frame = ethernet(gateway_mac, 0x0800U);
    const auto header = ipv4(
        source,
        destination,
        17U,
        udp_datagram(source_port, destination_port, payload, source, destination));
    frame.insert(frame.end(), header.begin(), header.end());
    return frame;
}

bytes arp_frame(const bool reply) {
    auto frame = ethernet(reply ? host_mac : gateway_mac, 0x0806U);
    const std::uint8_t operation = reply ? 0x02U : 0x01U;
    frame.insert(frame.end(), {0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, operation});
    const auto& sender_mac = reply ? host_mac : gateway_mac;
    const auto& target_mac = reply ? gateway_mac : host_mac;
    frame.insert(frame.end(), sender_mac.begin(), sender_mac.end());
    if (reply) {
        frame.insert(frame.end(), {192, 168, 1, 10});
        frame.insert(frame.end(), target_mac.begin(), target_mac.end());
        frame.insert(frame.end(), {192, 168, 1, 1});
    } else {
        frame.insert(frame.end(), {192, 168, 1, 1});
        frame.insert(frame.end(), target_mac.begin(), target_mac.end());
        frame.insert(frame.end(), {192, 168, 1, 10});
    }
    return frame;
}

struct sample {
    bytes frame;
    std::optional<netscope::packet::process_owner> owner;
    std::string note;
};

std::vector<sample> build_samples() {
    constexpr std::array<std::uint8_t, 4> web_host{93, 184, 216, 34};
    constexpr std::array<std::uint8_t, 4> cdn_host{151, 101, 1, 69};
    constexpr std::array<std::uint8_t, 4> dns_host{8, 8, 8, 8};

    const netscope::packet::process_owner safari{"Safari", 1842};
    const netscope::packet::process_owner curl{"curl", 5511};
    const netscope::packet::process_owner responder{"mDNSResponder", 231};

    const std::string request =
        "GET /index.html HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "User-Agent: Mozilla/5.0 (Macintosh)\r\n"
        "Accept: text/html,application/xhtml+xml\r\n\r\n";
    const std::string response =
        "HTTP/1.1 200 OK\r\n"
        "Date: Thu, 12 Nov 2026 08:15:02 GMT\r\n"
        "Server: nginx/1.25.3\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: 1256\r\n\r\n";
    const std::string login =
        "POST /login HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n";

    std::vector<sample> samples;
    samples.push_back({arp_frame(false), std::nullopt, "ARP request"});
    samples.push_back({arp_frame(true), std::nullopt, "ARP reply"});
    samples.push_back({udp_frame(host_ip, 60412, dns_host, 53, dns_query()), responder, "DNS query"});
    samples.push_back({udp_frame(dns_host, 53, host_ip, 60412, dns_response()), responder, "DNS response"});
    samples.push_back({tcp_frame(host_ip, 50514, web_host, 80, 1000, 0, 0x02), safari, "SYN"});
    samples.push_back({tcp_frame(web_host, 80, host_ip, 50514, 5000, 1001, 0x12), safari, "SYN/ACK"});
    samples.push_back({tcp_frame(host_ip, 50514, web_host, 80, 1001, 5001, 0x10), safari, "ACK"});
    samples.push_back({tcp_frame(host_ip, 50514, web_host, 80, 1001, 5001, 0x18, as_bytes(request)), safari, "HTTP GET"});
    samples.push_back({tcp_frame(web_host, 80, host_ip, 50514, 5001, 1001 + static_cast<std::uint32_t>(request.size()), 0x18, as_bytes(response)), safari, "HTTP 200"});
    samples.push_back({tcp_frame(host_ip, 50514, web_host, 80, 1001 + static_cast<std::uint32_t>(request.size()), 5001 + static_cast<std::uint32_t>(response.size()), 0x10), safari, "ACK"});
    samples.push_back({tcp_frame(host_ip, 50514, web_host, 80, 1001 + static_cast<std::uint32_t>(request.size()), 5001 + static_cast<std::uint32_t>(response.size()), 0x18, as_bytes(login)), safari, "HTTP POST"});
    samples.push_back({tcp_frame(host_ip, 50514, web_host, 80, 1001 + static_cast<std::uint32_t>(request.size() + login.size()), 5001 + static_cast<std::uint32_t>(response.size()), 0x11), safari, "FIN"});
    samples.push_back({tcp_frame(host_ip, 50520, cdn_host, 443, 7000, 0, 0x02), safari, "SYN"});
    samples.push_back({tcp_frame(cdn_host, 443, host_ip, 50520, 9000, 7001, 0x12), safari, "SYN/ACK"});
    samples.push_back({tcp_frame(host_ip, 50520, cdn_host, 443, 7001, 9001, 0x18, tls_client_hello("cdn.example.net")), safari, "TLS ClientHello"});
    samples.push_back({tcp_frame(cdn_host, 443, host_ip, 50520, 9001, 7001 + 120U, 0x10), safari, "ACK"});
    samples.push_back({tcp_frame(host_ip, 52001, cdn_host, 443, 3000, 0, 0x02), curl, "SYN"});
    samples.push_back({tcp_frame(cdn_host, 443, host_ip, 52001, 4000, 3001, 0x12), curl, "SYN/ACK"});
    samples.push_back({tcp_frame(host_ip, 52001, cdn_host, 443, 3001, 4001, 0x18, tls_client_hello("api.example.net")), curl, "TLS ClientHello"});
    samples.push_back({ip_frame(host_ip, {1, 1, 1, 1}, 1U, icmp_echo(0x4d2U, 1U)), std::nullopt, "ICMP echo"});
    samples.push_back({ip_frame({1, 1, 1, 1}, host_ip, 1U, icmp_echo(0x4d2U, 1U)), std::nullopt, "ICMP reply"});
    samples.push_back({bytes{0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00}, std::nullopt, "truncated"});
    return samples;
}

void pump() {
    for (int index = 0; index < 8; ++index) {
        QApplication::processEvents();
    }
}

void save(QWidget& widget, const std::filesystem::path& path) {
    pump();
    if (!widget.grab().save(QString::fromStdString(path.string()))) {
        throw std::runtime_error{"unable to save " + path.string()};
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    QApplication application{argc, argv};
    QApplication::setApplicationName(QStringLiteral("NetScope Screenshots"));

    const std::filesystem::path output =
        argc > 1 ? std::filesystem::path{argv[1]} : std::filesystem::path{"docs/figures"};
    std::filesystem::create_directories(output);

    netscope::analysis::process_tracker::snapshot_provider provider{[] {
        return std::vector<netscope::analysis::process_socket>{
            {"tcp", "192.168.1.10", 50514, "93.184.216.34", 80, "Safari", 1842},
            {"tcp", "192.168.1.10", 50520, "151.101.1.69", 443, "Safari", 1842},
            {"tcp", "192.168.1.10", 52001, "151.101.1.69", 443, "curl", 5511},
            {"udp", "192.168.1.10", 60412, "8.8.8.8", 53, "mDNSResponder", 231},
        };
    }};

    netscope::capture::capture_runner::opener opener{
        [](const std::string&,
           const netscope::capture::capture_options&) -> netscope::capture::capture_session {
            throw std::runtime_error{"capture is unavailable in the screenshot tool"};
        }};

    netscope::ui::main_window window{
        std::move(opener),
        [](const std::string&) -> std::optional<std::string> { return std::nullopt; },
        std::move(provider)};

    window.resize(1680, 1040);
    window.show();
    pump();

    netscope::packet::packet_repository repository{4096U};
    auto timestamp = std::chrono::system_clock::now() - std::chrono::minutes{3};
    std::vector<std::size_t> http_row;
    for (const auto& item : build_samples()) {
        timestamp += std::chrono::milliseconds{37};
        auto frame = item.frame;
        netscope::capture::captured_packet packet{
            timestamp,
            static_cast<std::uint32_t>(frame.size()),
            static_cast<std::uint32_t>(frame.size()),
            std::move(frame),
        };
        window.append_packet(repository.append(
            netscope::capture::merged_packet{std::move(packet), {"en0"}},
            item.owner));
        if (item.note == "HTTP GET") {
            http_row.push_back(repository.size() - 1U);
        }
    }
    pump();

    auto* const packet_table =
        window.findChild<QTableView*>(QStringLiteral("packetTable"));
    auto* const flow_table =
        window.findChild<QTableView*>(QStringLiteral("tcpFlowTable"));
    auto* const filter_edit =
        window.findChild<QLineEdit*>(QStringLiteral("displayFilterEdit"));
    auto* const flow_filter =
        window.findChild<QComboBox*>(QStringLiteral("flowProcessFilter"));
    auto* const capture_dock =
        window.findChild<QDockWidget*>(QStringLiteral("captureDock"));
    auto* const flow_dock =
        window.findChild<QDockWidget*>(QStringLiteral("tcpFlowDock"));
    auto* const statistics_dock =
        window.findChild<QDockWidget*>(QStringLiteral("statisticsDock"));
    auto* const anomaly_dock =
        window.findChild<QDockWidget*>(QStringLiteral("anomalyDock"));
    if (packet_table == nullptr || flow_table == nullptr || filter_edit == nullptr ||
        flow_filter == nullptr || flow_dock == nullptr || statistics_dock == nullptr ||
        anomaly_dock == nullptr) {
        qFatal("NetScope window is missing expected widgets");
    }

    const std::vector<int> packet_widths{45, 185, 60, 120, 130, 85, 135, 95, 70, 65};
    for (int column = 0; column < static_cast<int>(packet_widths.size()); ++column) {
        packet_table->setColumnWidth(column, packet_widths[static_cast<std::size_t>(column)]);
    }
    const std::vector<int> flow_widths{45, 185, 185, 120, 100, 75, 75, 90, 70, 90};
    for (int column = 0; column < static_cast<int>(flow_widths.size()); ++column) {
        flow_table->setColumnWidth(column, flow_widths[static_cast<std::size_t>(column)]);
    }

    flow_dock->hide();
    statistics_dock->hide();
    anomaly_dock->hide();
    if (!http_row.empty()) {
        packet_table->selectRow(static_cast<int>(http_row.front()));
        pump();
    }
    save(window, output / "main-window.png");

    flow_dock->show();
    flow_filter->setCurrentIndex(flow_filter->findText(QStringLiteral("Safari")));
    flow_dock->raise();
    flow_table->selectRow(flow_table->model()->rowCount() > 1 ? 1 : 0);
    pump();
    save(window, output / "tcp-flow.png");

    flow_dock->hide();
    statistics_dock->show();
    statistics_dock->raise();
    pump();
    save(window, output / "statistics.png");

    statistics_dock->hide();
    anomaly_dock->show();
    anomaly_dock->raise();
    pump();
    save(window, output / "observations.png");

    anomaly_dock->hide();
    flow_dock->hide();
    filter_edit->setText(QStringLiteral("http or tls"));
    QMetaObject::invokeMethod(filter_edit, "returnPressed");
    pump();
    save(window, output / "display-filter.png");

    if (capture_dock != nullptr) {
        capture_dock->show();
    }
    filter_edit->clear();
    QMetaObject::invokeMethod(filter_edit, "returnPressed");
    pump();

    return 0;
}
