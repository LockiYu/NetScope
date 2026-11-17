#pragma once

#include <chrono>
#include <string>
#include <string_view>

namespace netscope::capture {

struct temporary_bpf_access_result {
    bool granted{false};
    std::string error;
};

[[nodiscard]] bool is_macos_bpf_permission_error(
    std::string_view message) noexcept;

[[nodiscard]] temporary_bpf_access_result request_temporary_macos_bpf_access(
    std::chrono::milliseconds watch_duration = std::chrono::seconds{15});

}  // namespace netscope::capture
