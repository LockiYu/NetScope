#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace netscope::analysis {

class reverse_dns_resolver final {
public:
    using lookup = std::function<std::optional<std::string>(const std::string&)>;
    using callback =
        std::function<void(const std::string&, std::optional<std::string>)>;

    explicit reverse_dns_resolver(
        lookup resolve = system_lookup,
        std::chrono::seconds positive_ttl = std::chrono::minutes{30},
        std::chrono::seconds negative_ttl = std::chrono::minutes{5},
        std::size_t worker_count = 2U);
    ~reverse_dns_resolver();

    reverse_dns_resolver(const reverse_dns_resolver&) = delete;
    reverse_dns_resolver& operator=(const reverse_dns_resolver&) = delete;
    reverse_dns_resolver(reverse_dns_resolver&&) = delete;
    reverse_dns_resolver& operator=(reverse_dns_resolver&&) = delete;

    void resolve(std::string address, callback on_result);
    void clear_cache();

    [[nodiscard]] static std::optional<std::string> system_lookup(
        const std::string& address);

private:
    struct shared_state;

    static void worker_loop(std::shared_ptr<shared_state> state);

    std::shared_ptr<shared_state> state_;
    std::vector<std::thread> workers_;
};

}  // namespace netscope::analysis
