#include "netscope/analysis/reverse_dns.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace netscope::analysis {

struct reverse_dns_resolver::shared_state {
    struct cache_entry {
        std::optional<std::string> hostname;
        std::chrono::steady_clock::time_point expires_at;
    };

    reverse_dns_resolver::lookup lookup;
    std::chrono::seconds positive_ttl{};
    std::chrono::seconds negative_ttl{};
    std::mutex mutex;
    std::condition_variable condition;
    std::condition_variable callbacks_done;
    bool stopping{false};
    std::deque<std::string> queue;
    std::unordered_map<std::string, cache_entry> cache;
    std::unordered_map<std::string, std::vector<reverse_dns_resolver::callback>> pending;
    std::size_t active_callback_batches{0U};
};

reverse_dns_resolver::reverse_dns_resolver(
    lookup resolve,
    const std::chrono::seconds positive_ttl,
    const std::chrono::seconds negative_ttl,
    const std::size_t worker_count)
    : state_{std::make_shared<shared_state>()} {
    if (!resolve) {
        throw std::invalid_argument{"reverse DNS lookup function must not be empty"};
    }
    if (positive_ttl <= std::chrono::seconds::zero() ||
        negative_ttl <= std::chrono::seconds::zero()) {
        throw std::invalid_argument{"reverse DNS cache TTL must be positive"};
    }
    if (worker_count == 0U) {
        throw std::invalid_argument{"reverse DNS worker count must be positive"};
    }
    state_->lookup = std::move(resolve);
    state_->positive_ttl = positive_ttl;
    state_->negative_ttl = negative_ttl;
    workers_.reserve(worker_count);
    for (std::size_t index = 0U; index < worker_count; ++index) {
        const auto state = state_;
        workers_.emplace_back([state] { worker_loop(state); });
    }
}

reverse_dns_resolver::~reverse_dns_resolver() {
    {
        const std::lock_guard lock{state_->mutex};
        state_->stopping = true;
        state_->queue.clear();
    }
    state_->condition.notify_all();

    // A worker may be blocked inside getnameinfo, which has no usable cancel
    // API. Detach such workers instead of joining them: the shared state keeps
    // them safe, and they stop as soon as the blocking lookup returns. Waiting
    // for a reverse lookup here used to freeze the application on quit.
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.detach();
        }
    }

    // Callbacks may touch the owning window. Wait briefly for a callback batch
    // that is already running, then leave any blocked lookup to finish alone.
    std::unique_lock lock{state_->mutex};
    state_->callbacks_done.wait_for(
        lock,
        std::chrono::milliseconds{500},
        [this] { return state_->active_callback_batches == 0U; });
}

void reverse_dns_resolver::resolve(std::string address, callback on_result) {
    if (address.empty()) {
        throw std::invalid_argument{"reverse DNS address must not be empty"};
    }
    if (!on_result) {
        throw std::invalid_argument{"reverse DNS callback must not be empty"};
    }

    std::optional<std::optional<std::string>> cached;
    bool queued{false};
    {
        const std::lock_guard lock{state_->mutex};
        if (state_->stopping) {
            return;
        }
        const auto now = std::chrono::steady_clock::now();
        const auto found = state_->cache.find(address);
        if (found != state_->cache.end() && found->second.expires_at > now) {
            cached = found->second.hostname;
        } else {
            if (found != state_->cache.end()) {
                state_->cache.erase(found);
            }
            auto pending = state_->pending.find(address);
            if (pending != state_->pending.end()) {
                pending->second.push_back(std::move(on_result));
                return;
            }
            state_->pending.emplace(
                address, std::vector<callback>{std::move(on_result)});
            state_->queue.push_back(address);
            queued = true;
        }
    }
    if (cached.has_value()) {
        on_result(address, cached.value());
        return;
    }
    if (queued) {
        state_->condition.notify_one();
    }
}

void reverse_dns_resolver::clear_cache() {
    const std::lock_guard lock{state_->mutex};
    state_->cache.clear();
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

void reverse_dns_resolver::worker_loop(std::shared_ptr<shared_state> state) {
    while (true) {
        std::string address;
        {
            std::unique_lock lock{state->mutex};
            state->condition.wait(lock, [&state] {
                return state->stopping || !state->queue.empty();
            });
            if (state->stopping) {
                return;
            }
            address = std::move(state->queue.front());
            state->queue.pop_front();
        }

        auto hostname = state->lookup(address);
        std::vector<callback> callbacks;
        {
            const std::lock_guard lock{state->mutex};
            if (state->stopping) {
                continue;
            }
            const auto ttl = hostname.has_value() ? state->positive_ttl : state->negative_ttl;
            state->cache[address] = shared_state::cache_entry{
                hostname,
                std::chrono::steady_clock::now() + ttl,
            };
            const auto found = state->pending.find(address);
            if (found != state->pending.end()) {
                callbacks = std::move(found->second);
                state->pending.erase(found);
            }
            if (!callbacks.empty()) {
                ++state->active_callback_batches;
            }
        }
        if (callbacks.empty()) {
            continue;
        }
        for (const auto& callback : callbacks) {
            callback(address, hostname);
        }
        {
            const std::lock_guard lock{state->mutex};
            if (state->active_callback_batches > 0U) {
                --state->active_callback_batches;
            }
            if (state->active_callback_batches == 0U) {
                state->callbacks_done.notify_all();
            }
        }
    }
}

}  // namespace netscope::analysis
