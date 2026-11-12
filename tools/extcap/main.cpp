// NetScope extcap plug-in for Wireshark.
//
// Implements the extcap contract so that Wireshark can list every local
// interface as "NetScope: <device>", start a NetScope capture, and receive a
// pcapng stream whose packets carry the owning process as a packet comment.
// The NetScope application itself stays independent of Wireshark; this binary
// is an optional interoperability bridge.
#include "netscope/capture/live_capture.h"
#include "netscope/extcap/packet_writer.h"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

namespace {

constexpr const char* extcap_version = "1.0.0";
constexpr const char* interface_prefix = "netscope_";
constexpr int ethernet_link_type = 1;

volatile std::sig_atomic_t interrupted = 0;

void handle_signal(int) {
    interrupted = 1;
}

struct invocation {
    std::map<std::string, std::string> values;
    bool contains(const std::string& key) const {
        return values.find(key) != values.end();
    }
    std::string value(const std::string& key) const {
        const auto found = values.find(key);
        return found == values.end() ? std::string{} : found->second;
    }
    int integer(const std::string& key, const int fallback) const {
        const auto text = value(key);
        if (text.empty()) {
            return fallback;
        }
        char* end{nullptr};
        const auto parsed = std::strtol(text.c_str(), &end, 10);
        if (end == text.c_str() || *end != '\0') {
            return fallback;
        }
        return static_cast<int>(parsed);
    }
};

invocation parse(const int argc, char* argv[]) {
    invocation result;
    for (int index = 1; index < argc; ++index) {
        std::string argument{argv[index]};
        if (argument.rfind("--", 0U) != 0U) {
            continue;
        }
        argument = argument.substr(2U);
        const auto equals = argument.find('=');
        if (equals == std::string::npos) {
            result.values.emplace(argument, std::string{});
        } else {
            result.values.emplace(
                argument.substr(0U, equals),
                argument.substr(equals + 1U));
        }
    }
    return result;
}

std::string display_for(const netscope::capture::network_interface& interface) {
    std::string display = "NetScope: " + interface.name;
    if (!interface.description.empty()) {
        display += " (" + interface.description + ")";
    } else if (interface.is_loopback) {
        display += " (loopback)";
    }
    return display;
}

void print_interfaces() {
    std::printf(
        "extcap {version=%s}{display=NetScope}{help=https://github.com/LockiYu/NetScope}\n",
        extcap_version);
    for (const auto& interface : netscope::capture::list_network_interfaces()) {
        if (interface.name.empty()) {
            continue;
        }
        std::printf(
            "interface {value=%s%s}{display=%s}\n",
            interface_prefix,
            interface.name.c_str(),
            display_for(interface).c_str());
    }
}

void print_dlts() {
    std::printf(
        "dlt {number=%d}{name=EN10MB}{display=Ethernet}\n", ethernet_link_type);
}

void print_config() {
    std::printf(
        "arg {number=0}{call=--filter}{display=Capture filter}"
        "{type=string}{tooltip=libpcap BPF expression, for example tcp port 443}"
        "{required=false}\n");
    std::printf(
        "arg {number=1}{call=--snaplen}{display=Snapshot length}"
        "{type=integer}{range=1,1048576}{default=262144}"
        "{tooltip=Bytes captured from each packet}\n");
    std::printf(
        "arg {number=2}{call=--no-processes}{display=Disable process names}"
        "{type=boolflag}{tooltip=Do not add process comments to packets}\n");
    std::printf(
        "arg {number=3}{call=--refresh}{display=Process refresh (seconds)}"
        "{type=integer}{range=1,60}{default=5}"
        "{tooltip=How often the socket to process map is refreshed}\n");
}

bool write_all(const int descriptor, const std::uint8_t* data, std::size_t size) {
    while (size > 0U) {
        const auto written = ::write(descriptor, data, size);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        data += written;
        size -= static_cast<std::size_t>(written);
    }
    return true;
}

std::string device_from_interface(const std::string& value) {
    const std::string prefix{interface_prefix};
    if (value.rfind(prefix, 0U) != 0U) {
        return {};
    }
    return value.substr(prefix.size());
}

std::string description_for(const std::string& device) {
    try {
        for (const auto& interface : netscope::capture::list_network_interfaces()) {
            if (interface.name == device) {
                return interface.description;
            }
        }
    } catch (const std::exception&) {
        return {};
    }
    return {};
}

int run_capture(const invocation& arguments) {
    const auto device = device_from_interface(arguments.value("extcap-interface"));
    const auto fifo = arguments.value("fifo");
    if (device.empty()) {
        std::fprintf(stderr, "netscope-extcap: unknown extcap interface '%s'\n",
                     arguments.value("extcap-interface").c_str());
        return 1;
    }
    if (fifo.empty()) {
        std::fprintf(stderr, "netscope-extcap: --fifo is required\n");
        return 1;
    }

    netscope::capture::capture_options options;
    options.snapshot_length = arguments.integer("snaplen", options.snapshot_length);
    options.bpf_filter = arguments.value("filter");
    options.promiscuous = true;

    std::optional<netscope::capture::capture_session> session;
    try {
        session.emplace(netscope::capture::open_live_capture(device, options));
    } catch (const std::exception& error) {
        std::fprintf(stderr, "netscope-extcap: %s\n", error.what());
        return 1;
    }

    const int descriptor = ::open(fifo.c_str(), O_WRONLY);
    if (descriptor < 0) {
        std::fprintf(stderr, "netscope-extcap: cannot open %s: %s\n",
                     fifo.c_str(), std::strerror(errno));
        return 1;
    }

    netscope::extcap::writer_options writer_options;
    writer_options.interface_name = device;
    writer_options.description = description_for(device);
    writer_options.snapshot_length = options.snapshot_length;
    writer_options.attach_processes = !arguments.contains("no-processes");
    writer_options.process_refresh = std::chrono::seconds{
        arguments.integer("refresh", 5)};
    if (writer_options.process_refresh.count() < 1 ||
        writer_options.process_refresh.count() > 60) {
        writer_options.process_refresh = std::chrono::seconds{5};
    }

    netscope::extcap::packet_writer writer{
        [descriptor](const std::uint8_t* data, const std::size_t size) {
            return write_all(descriptor, data, size);
        },
        std::move(writer_options)};

    if (!writer.write_header()) {
        ::close(descriptor);
        return 1;
    }

    while (interrupted == 0) {
        if (auto packet = session->next_packet(); packet.has_value()) {
            if (!writer.write_packet(packet.value())) {
                break;
            }
        }
        pollfd poll_descriptor{descriptor, POLLOUT, 0};
        const int ready = ::poll(&poll_descriptor, 1, 0);
        if (ready > 0 &&
            (poll_descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            break;
        }
    }

    session->stop();
    ::close(descriptor);
    return 0;
}

void print_usage() {
    std::printf(
        "netscope-extcap %s\n"
        "  --extcap-interfaces\n"
        "  --extcap-dlts --extcap-interface=<iface>\n"
        "  --extcap-config --extcap-interface=<iface>\n"
        "  --capture --extcap-interface=<iface> --fifo=<path>\n",
        extcap_version);
}

}  // namespace

int main(int argc, char* argv[]) {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    std::signal(SIGPIPE, SIG_IGN);

    const auto arguments = parse(argc, argv);
    try {
        if (arguments.contains("extcap-interfaces")) {
            print_interfaces();
            return 0;
        }
        if (arguments.contains("extcap-dlts")) {
            print_dlts();
            return 0;
        }
        if (arguments.contains("extcap-config")) {
            print_config();
            return 0;
        }
        if (arguments.contains("capture")) {
            return run_capture(arguments);
        }
        if (arguments.contains("help")) {
            print_usage();
            return 0;
        }
    } catch (const std::exception& error) {
        std::fprintf(stderr, "netscope-extcap: %s\n", error.what());
        return 1;
    }
    print_usage();
    return 1;
}
