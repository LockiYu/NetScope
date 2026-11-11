#include "netscope/analysis/reverse_dns.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace {

using namespace std::chrono_literals;
using netscope::analysis::reverse_dns_resolver;

TEST(reverse_dns_test, deduplicates_concurrent_requests_and_caches_successes) {
    std::atomic<int> lookups{0};
    reverse_dns_resolver resolver{
        [&](const std::string& address) -> std::optional<std::string> {
            ++lookups;
            std::this_thread::sleep_for(10ms);
            return address == "192.0.2.1" ? std::optional<std::string>{"host.example"}
                                          : std::nullopt;
        },
        1h,
        1min,
        2U};
    std::mutex mutex;
    std::condition_variable ready;
    std::vector<std::optional<std::string>> results;
    const auto callback = [&](const std::string&, std::optional<std::string> hostname) {
        {
            const std::lock_guard lock{mutex};
            results.push_back(std::move(hostname));
        }
        ready.notify_all();
    };

    resolver.resolve("192.0.2.1", callback);
    resolver.resolve("192.0.2.1", callback);
    {
        std::unique_lock lock{mutex};
        ASSERT_TRUE(ready.wait_for(lock, 1s, [&] { return results.size() == 2U; }));
    }
    resolver.resolve("192.0.2.1", callback);
    {
        std::unique_lock lock{mutex};
        ASSERT_TRUE(ready.wait_for(lock, 1s, [&] { return results.size() == 3U; }));
    }

    EXPECT_EQ(lookups.load(), 1);
    ASSERT_TRUE(results.back().has_value());
    EXPECT_EQ(results.back().value(), "host.example");
}

TEST(reverse_dns_test, negatively_caches_failed_lookups) {
    std::atomic<int> lookups{0};
    reverse_dns_resolver resolver{
        [&](const std::string&) -> std::optional<std::string> {
            ++lookups;
            return std::nullopt;
        }};
    std::mutex mutex;
    std::condition_variable ready;
    int callbacks{0};
    const auto callback = [&](const std::string&, std::optional<std::string> hostname) {
        EXPECT_FALSE(hostname.has_value());
        {
            const std::lock_guard lock{mutex};
            ++callbacks;
        }
        ready.notify_all();
    };

    resolver.resolve("198.51.100.9", callback);
    {
        std::unique_lock lock{mutex};
        ASSERT_TRUE(ready.wait_for(lock, 1s, [&] { return callbacks == 1; }));
    }
    resolver.resolve("198.51.100.9", callback);
    {
        std::unique_lock lock{mutex};
        ASSERT_TRUE(ready.wait_for(lock, 1s, [&] { return callbacks == 2; }));
    }
    EXPECT_EQ(lookups.load(), 1);
}

TEST(reverse_dns_test, rejects_empty_addresses) {
    reverse_dns_resolver resolver;
    EXPECT_THROW(
        resolver.resolve("", [](const std::string&, std::optional<std::string>) {}),
        std::invalid_argument);
}

}  // namespace
