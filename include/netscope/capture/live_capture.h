#pragma once

#include "netscope/capture/pcap_file.h"

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace netscope::capture {

struct interface_address {
    std::string address;
    std::string netmask;
};

struct network_interface {
    std::string name;
    std::string description;
    std::vector<interface_address> addresses;
    bool is_up{false};
    bool is_running{false};
    bool is_loopback{false};
    bool is_wireless{false};
    bool is_tunnel{false};
};

[[nodiscard]] std::vector<network_interface> list_network_interfaces();
[[nodiscard]] bool should_select_by_default(const network_interface& interface) noexcept;

[[nodiscard]] std::optional<std::string> validate_bpf_filter(
    const std::string& expression,
    int link_type,
    int snapshot_length);

struct capture_options {
    int snapshot_length{262144};
    bool promiscuous{true};
    std::chrono::milliseconds read_timeout{100};
    int buffer_size{4 * 1024 * 1024};
    bool immediate_mode{true};
    std::string bpf_filter;
};

struct capture_statistics {
    std::uint32_t received{0};
    std::uint32_t dropped{0};
    std::uint32_t interface_dropped{0};
};

enum class capture_state {
    active,
    paused,
    stopped,
};

class capture_backend {
public:
    virtual ~capture_backend() = default;
    [[nodiscard]] virtual std::optional<captured_packet> next_packet() = 0;
    virtual void break_capture() noexcept = 0;
    [[nodiscard]] virtual capture_statistics statistics() const = 0;
};

class capture_session final {
public:
    capture_session(std::unique_ptr<capture_backend> backend, std::string interface_name);
    ~capture_session();

    capture_session(const capture_session&) = delete;
    capture_session& operator=(const capture_session&) = delete;
    capture_session(capture_session&&) noexcept = default;
    capture_session& operator=(capture_session&&) noexcept = default;

    [[nodiscard]] capture_state state() const noexcept;
    [[nodiscard]] const std::string& interface_name() const noexcept;
    [[nodiscard]] std::optional<captured_packet> next_packet();
    [[nodiscard]] capture_statistics statistics() const;
    void pause() noexcept;
    void resume() noexcept;
    void stop() noexcept;

private:
    std::unique_ptr<capture_backend> backend_;
    std::string interface_name_;
    capture_state state_{capture_state::active};
};

[[nodiscard]] std::optional<std::string> validate_capture_options(
    const capture_options& options) noexcept;

[[nodiscard]] capture_session open_live_capture(
    const std::string& interface_name,
    const capture_options& options = {});

}  // namespace netscope::capture

