#include "netscope/capture/live_capture.h"

#include <pcap/pcap.h>

#include <netdb.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace netscope::capture {
namespace {

struct device_list_closer {
    void operator()(pcap_if_t* devices) const noexcept {
        if (devices != nullptr) {
            pcap_freealldevs(devices);
        }
    }
};

struct pcap_closer {
    void operator()(pcap_t* handle) const noexcept {
        if (handle != nullptr) {
            pcap_close(handle);
        }
    }
};

struct bpf_program_closer {
    void operator()(bpf_program* program) const noexcept {
        if (program != nullptr) {
            pcap_freecode(program);
        }
    }
};

using device_list = std::unique_ptr<pcap_if_t, device_list_closer>;
using pcap_handle = std::unique_ptr<pcap_t, pcap_closer>;
using compiled_filter = std::unique_ptr<bpf_program, bpf_program_closer>;

class libpcap_backend final : public capture_backend {
public:
    explicit libpcap_backend(pcap_handle handle) : handle_{std::move(handle)} {}

    std::optional<captured_packet> next_packet() override {
        pcap_pkthdr* header{nullptr};
        const u_char* data{nullptr};
        const int status = pcap_next_ex(handle_.get(), &header, &data);
        if (status == 0 || status == -2) {
            return std::nullopt;
        }
        if (status == -1) {
            throw std::runtime_error{
                "live capture failed: " + std::string{pcap_geterr(handle_.get())}};
        }
        if (header == nullptr || (header->caplen != 0U && data == nullptr)) {
            throw std::runtime_error{"libpcap returned an invalid live packet"};
        }

        captured_packet packet;
        const auto seconds = std::chrono::seconds{
            static_cast<std::chrono::seconds::rep>(header->ts.tv_sec)};
        const auto microseconds = std::chrono::microseconds{
            static_cast<std::chrono::microseconds::rep>(header->ts.tv_usec)};
        packet.timestamp = std::chrono::system_clock::time_point{seconds + microseconds};
        packet.captured_length = header->caplen;
        packet.original_length = header->len;
        if (header->caplen != 0U) {
            packet.bytes.assign(data, data + header->caplen);
        }
        return packet;
    }

    void break_capture() noexcept override {
        pcap_breakloop(handle_.get());
    }

    capture_statistics statistics() const override {
        pcap_stat values{};
        if (pcap_stats(handle_.get(), &values) != 0) {
            throw std::runtime_error{
                "failed to read capture statistics: " +
                std::string{pcap_geterr(handle_.get())}};
        }
        return capture_statistics{values.ps_recv, values.ps_drop, values.ps_ifdrop};
    }

private:
    pcap_handle handle_;
};

std::string numeric_address(const sockaddr* const address) {
    if (address == nullptr) {
        return {};
    }
    if (address->sa_family != AF_INET && address->sa_family != AF_INET6) {
        return {};
    }

    std::array<char, NI_MAXHOST> host{};
    const auto length = address->sa_family == AF_INET
        ? static_cast<socklen_t>(sizeof(sockaddr_in))
        : static_cast<socklen_t>(sizeof(sockaddr_in6));
    const int result = getnameinfo(
        address,
        length,
        host.data(),
        static_cast<socklen_t>(host.size()),
        nullptr,
        0,
        NI_NUMERICHOST);
    return result == 0 ? std::string{host.data()} : std::string{};
}

bool has_prefix(const std::string& value, const std::string& prefix) noexcept {
    return value.size() >= prefix.size() &&
           value.compare(0U, prefix.size(), prefix) == 0;
}

}  // namespace

std::vector<network_interface> list_network_interfaces() {
    std::array<char, PCAP_ERRBUF_SIZE> error_buffer{};
    pcap_if_t* raw_devices{nullptr};
    if (pcap_findalldevs(&raw_devices, error_buffer.data()) != 0) {
        throw std::runtime_error{
            "failed to enumerate capture interfaces: " + std::string{error_buffer.data()}};
    }
    device_list devices{raw_devices};

    std::vector<network_interface> result;
    for (const pcap_if_t* device = devices.get(); device != nullptr; device = device->next) {
        network_interface item;
        item.name = device->name == nullptr ? std::string{} : std::string{device->name};
        item.description = device->description == nullptr
            ? std::string{}
            : std::string{device->description};
        item.is_up = (device->flags & PCAP_IF_UP) != 0U;
        item.is_running = (device->flags & PCAP_IF_RUNNING) != 0U;
        item.is_loopback = (device->flags & PCAP_IF_LOOPBACK) != 0U;
#ifdef PCAP_IF_WIRELESS
        item.is_wireless = (device->flags & PCAP_IF_WIRELESS) != 0U;
#endif
        item.is_tunnel = has_prefix(item.name, "utun") ||
                         has_prefix(item.name, "tun") ||
                         has_prefix(item.name, "tap");

        for (const pcap_addr_t* address = device->addresses;
             address != nullptr;
             address = address->next) {
            const auto numeric = numeric_address(address->addr);
            if (numeric.empty()) {
                continue;
            }
            item.addresses.push_back(interface_address{
                numeric,
                numeric_address(address->netmask),
            });
        }
        result.push_back(std::move(item));
    }

    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        const bool left_default = should_select_by_default(left);
        const bool right_default = should_select_by_default(right);
        if (left_default != right_default) {
            return left_default;
        }
        return left.name < right.name;
    });
    return result;
}

bool should_select_by_default(const network_interface& interface) noexcept {
    return interface.is_up && interface.is_running &&
           !interface.is_loopback && !interface.is_tunnel;
}

std::optional<std::string> validate_bpf_filter(
    const std::string& expression,
    const int link_type,
    const int snapshot_length) {
    if (expression.empty()) {
        return std::nullopt;
    }
    if (snapshot_length <= 0) {
        return std::string{"snapshot length must be positive"};
    }

    pcap_handle handle{pcap_open_dead(link_type, snapshot_length)};
    if (!handle) {
        return std::string{"failed to create BPF compiler context"};
    }

    auto program = std::make_unique<bpf_program>();
    if (pcap_compile(
            handle.get(), program.get(), expression.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        return std::string{pcap_geterr(handle.get())};
    }
    compiled_filter owned_program{program.release()};
    return std::nullopt;
}

capture_session::capture_session(
    std::unique_ptr<capture_backend> backend,
    std::string interface_name)
    : backend_{std::move(backend)}, interface_name_{std::move(interface_name)} {
    if (!backend_) {
        throw std::invalid_argument{"capture backend must not be null"};
    }
}

capture_session::~capture_session() {
    stop();
}

capture_session::capture_session(capture_session&& other) noexcept
    : backend_{std::move(other.backend_)},
      interface_name_{std::move(other.interface_name_)},
      state_{other.state_.exchange(capture_state::stopped)} {}

capture_session& capture_session::operator=(capture_session&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    stop();
    backend_ = std::move(other.backend_);
    interface_name_ = std::move(other.interface_name_);
    state_.store(other.state_.exchange(capture_state::stopped));
    return *this;
}

capture_state capture_session::state() const noexcept {
    return state_.load();
}

const std::string& capture_session::interface_name() const noexcept {
    return interface_name_;
}

std::optional<captured_packet> capture_session::next_packet() {
    if (state_.load() != capture_state::active) {
        return std::nullopt;
    }
    return backend_->next_packet();
}

capture_statistics capture_session::statistics() const {
    return backend_->statistics();
}

void capture_session::pause() noexcept {
    auto expected = capture_state::active;
    static_cast<void>(state_.compare_exchange_strong(expected, capture_state::paused));
}

void capture_session::resume() noexcept {
    auto expected = capture_state::paused;
    static_cast<void>(state_.compare_exchange_strong(expected, capture_state::active));
}

void capture_session::stop() noexcept {
    if (state_.exchange(capture_state::stopped) != capture_state::stopped) {
        if (backend_) {
            backend_->break_capture();
        }
    }
}

std::optional<std::string> validate_capture_options(
    const capture_options& options) noexcept {
    if (options.snapshot_length <= 0 || options.snapshot_length > 1048576) {
        return std::string{"snapshot length must be between 1 and 1048576 bytes"};
    }
    if (options.read_timeout.count() < 0 ||
        options.read_timeout.count() > std::numeric_limits<int>::max()) {
        return std::string{"read timeout is outside the supported range"};
    }
    if (options.buffer_size <= 0) {
        return std::string{"capture buffer size must be positive"};
    }
    return std::nullopt;
}

capture_session open_live_capture(
    const std::string& interface_name,
    const capture_options& options) {
    if (interface_name.empty()) {
        throw std::invalid_argument{"capture interface name must not be empty"};
    }
    if (const auto error = validate_capture_options(options); error.has_value()) {
        throw std::invalid_argument{error.value()};
    }

    std::array<char, PCAP_ERRBUF_SIZE> error_buffer{};
    pcap_handle handle{pcap_create(interface_name.c_str(), error_buffer.data())};
    if (!handle) {
        throw std::runtime_error{
            "failed to create capture on '" + interface_name + "': " +
            error_buffer.data()};
    }

    const auto require_configuration = [&](const int result, const char* setting) {
        if (result != 0) {
            throw std::runtime_error{
                "failed to configure " + std::string{setting} + " on '" +
                interface_name + "': " + pcap_geterr(handle.get())};
        }
    };

    require_configuration(
        pcap_set_snaplen(handle.get(), options.snapshot_length), "snapshot length");
    require_configuration(
        pcap_set_promisc(handle.get(), options.promiscuous ? 1 : 0), "promiscuous mode");
    require_configuration(
        pcap_set_timeout(
            handle.get(), static_cast<int>(options.read_timeout.count())),
        "read timeout");
    require_configuration(
        pcap_set_buffer_size(handle.get(), options.buffer_size), "capture buffer size");
    if (options.immediate_mode) {
        require_configuration(pcap_set_immediate_mode(handle.get(), 1), "immediate mode");
    }

    const int activation = pcap_activate(handle.get());
    if (activation < 0) {
        throw std::runtime_error{
            "failed to activate capture on '" + interface_name + "': " +
            pcap_geterr(handle.get())};
    }

    if (!options.bpf_filter.empty()) {
        auto program = std::make_unique<bpf_program>();
        if (pcap_compile(
                handle.get(), program.get(), options.bpf_filter.c_str(), 1,
                PCAP_NETMASK_UNKNOWN) != 0) {
            throw std::runtime_error{
                "invalid BPF filter: " + std::string{pcap_geterr(handle.get())}};
        }
        compiled_filter owned_program{program.release()};
        if (pcap_setfilter(handle.get(), owned_program.get()) != 0) {
            throw std::runtime_error{
                "failed to apply BPF filter: " + std::string{pcap_geterr(handle.get())}};
        }
    }

    return capture_session{
        std::make_unique<libpcap_backend>(std::move(handle)), interface_name};
}

}  // namespace netscope::capture

