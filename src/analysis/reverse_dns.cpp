#include "netscope/analysis/reverse_dns.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace netscope::analysis {

reverse_dns_resolver::reverse_dns_resolver(
    lookup resolve,
    const std::chrono::seconds positive_ttl,
    const std::chrono::seconds negative_ttl,
    const std::size_t worker_count)
    : lookup_{std::move(resolve)},
      positive_ttl_{positive_ttl},
      negative_ttl_{negative_ttl} {
    if (!lookup_) {
        throw std::invalid_argument{"reverse DNS lookup function must not be empty"};
    }
    if (positive_ttl_ <= std::chrono::seconds::zero() ||
        negative_ttl_ <= std::chrono::seconds::zero()) {
        throw std::invalid_argument{"reverse DNS cache TTL must be positive"};
    }
    if (worker_count == 0U) {
        throw std::invalid_argument{"reverse DNS worker count must be positive"};
    }
    workers_.reserve(worker_count);
    for (std::size_t index = 0U; index < worker_count; ++index) {
        workers_.emplace_back([this] { worker_loop(); });
    }
}

reverse_dns_resolver::~reverse_dns_resolver() {
    {
        const std::lock_guard lock{mutex_};
        stopping_ = true;
    }
    condition_.notify_all();
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void reverse_dns_resolver::resolve(std::string address, callback on_result) {
    if (address.empty()) {
        throw std::invalid_argument{"reverse DNS address must not be empty"};
    }
    if (!on_result) {
        throw std::invalid_argument{"reverse DNS callback must not be empty"};
    }

    std::optional<std::optional<std::string>> cached;
    {
        const std::lock_guard lock{mutex_};
        if (stopping_) {
            return;
        }
        const auto now = std::chrono::steady_clock::now();
        const auto found = cache_.find(address);
        if (found != cache_.end() && found->second.expires_at > now) {
            cached = found->second.hostname;
        } else {
            if (found != cache_.end()) {
                cache_.erase(found);
            }
            auto pending = pending_.find(address);
            if (pending != pending_.end()) {
                pending->second.push_back(std::move(on_result));
                return;
            }
            pending_.emplace(address, std::vector<callback>{std::move(on_result)});
            queue_.push_back(address);
        }
    }
    if (cached.has_value()) {
        on_result(address, cached.value());
        return;
    }
    condition_.notify_one();
}

void reverse_dns_resolver::clear_cache() {
    const std::lock_guard lock{mutex_};
    cache_.clear();
}

std::optional<std::string> reverse_dns_resolver::system_lookup(
    const std::string& address) {
    sockaddr_storage storage{};
    socklen_t length{0};
    auto* const ipv4 = reinterpret_cast<sockaddr_in*>(&storage);
    auto* const ipv6 = reinterpret_cast<sockaddr_in6*>(&storage);
    if (inet_pton(AF_INET, address.c_str(), &ipv4->sin_addr) == 1) {
        ipv4->sin_family = AF_INET;
        length = static_cast<socklen_t>(sizeof(sockaddr_in));
    } else if (inet_pton(AF_INET6, address.c_str(), &ipv6->sin6_addr) == 1) {
        ipv6->sin6_family = AF_INET6;
        length = static_cast<socklen_t>(sizeof(sockaddr_in6));
    } else {
        return std::nullopt;
    }

    std::array<char, NI_MAXHOST> hostname{};
    const int result = getnameinfo(
        reinterpret_cast<const sockaddr*>(&storage),
        length,
        hostname.data(),
        static_cast<socklen_t>(hostname.size()),
        nullptr,
        0,
        NI_NAMEREQD);
    if (result != 0) {
        return std::nullopt;
    }
    return std::string{hostname.data()};
}

void reverse_dns_resolver::worker_loop() {
    while (true) {
        std::string address;
        {
            std::unique_lock lock{mutex_};
            condition_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
            if (stopping_ && queue_.empty()) {
                return;
            }
            address = std::move(queue_.front());
            queue_.pop_front();
        }

        auto hostname = lookup_(address);
        std::vector<callback> callbacks;
        {
            const std::lock_guard lock{mutex_};
            const auto ttl = hostname.has_value() ? positive_ttl_ : negative_ttl_;
            cache_[address] = cache_entry{
                hostname,
                std::chrono::steady_clock::now() + ttl,
            };
            const auto found = pending_.find(address);
            if (found != pending_.end()) {
                callbacks = std::move(found->second);
                pending_.erase(found);
            }
        }
        for (const auto& callback : callbacks) {
            callback(address, hostname);
        }
    }
}

}  // namespace netscope::analysis
