#include "netscope/analysis/packet_compare.h"

#include <map>
#include <set>

namespace netscope::analysis {
namespace {

void flatten(
    const protocol::protocol_node& node,
    const std::string& parent,
    std::map<std::string, std::string>& values) {
    const auto node_path = parent.empty() ? node.name : parent + '/' + node.name;
    for (const auto& field : node.fields) {
        values[node_path + '/' + field.name] = field.display_value;
    }
    for (const auto& child : node.children) {
        flatten(child, node_path, values);
    }
}

}  // namespace

std::vector<protocol_difference> compare_protocol_trees(
    const protocol::protocol_node& left,
    const protocol::protocol_node& right) {
    std::map<std::string, std::string> left_values;
    std::map<std::string, std::string> right_values;
    flatten(left, {}, left_values);
    flatten(right, {}, right_values);
    std::set<std::string> paths;
    for (const auto& [path, value] : left_values) {
        static_cast<void>(value);
        paths.insert(path);
    }
    for (const auto& [path, value] : right_values) {
        static_cast<void>(value);
        paths.insert(path);
    }
    std::vector<protocol_difference> result;
    for (const auto& path : paths) {
        const auto left_value = left_values.find(path);
        const auto right_value = right_values.find(path);
        const auto left_text = left_value == left_values.end() ? std::string{} : left_value->second;
        const auto right_text = right_value == right_values.end() ? std::string{} : right_value->second;
        if (left_text != right_text) {
            result.push_back(protocol_difference{path, left_text, right_text});
        }
    }
    return result;
}

}  // namespace netscope::analysis
