#pragma once

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

}  // namespace netscope::capture

