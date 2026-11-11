#pragma once

#include "netscope/protocol/protocol_model.h"

#include <string>
#include <vector>

namespace netscope::analysis {

struct protocol_difference {
    std::string path;
    std::string left_value;
    std::string right_value;
};

[[nodiscard]] std::vector<protocol_difference> compare_protocol_trees(
    const protocol::protocol_node& left,
    const protocol::protocol_node& right);

}  // namespace netscope::analysis
