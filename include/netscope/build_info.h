#pragma once

#include <string>

namespace netscope {

struct build_info {
    std::string qt_version;
    std::string pcap_version;
};

[[nodiscard]] build_info current_build_info();

}  // namespace netscope

