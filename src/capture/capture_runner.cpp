#include "netscope/capture/capture_runner.h"

#include <chrono>
#include <exception>
#include <stdexcept>
#include <utility>

namespace netscope::capture {

capture_runner::capture_runner(opener open) : open_{std::move(open)} {
    if (!open_) {
        throw std::invalid_argument{"capture opener must not be empty"};
    }
}

capture_runner::~capture_runner() {
    stop();
}

void capture_runner::start(
    const std::vector<std::string>& interfaces,
    const capture_options& options,
    packet_handler on_packet,
    error_handler on_error) {
    const std::lock_guard lock{lifecycle_mutex_};
    if (running_.load()) {
        throw std::logic_error{"capture runner is already active"};
    }
    if (interfaces.empty()) {
        throw std::invalid_argument{"at least one capture interface is required"};
    }
    if (!on_packet) {
        throw std::invalid_argument{"packet handler must not be empty"};
    }

    std::vector<std::unique_ptr<capture_session>> opened;
    opened.reserve(interfaces.size());
    for (const auto& interface : interfaces) {
        opened.push_back(std::make_unique<capture_session>(open_(interface, options)));
    }
    sessions_ = std::move(opened);
    workers_.clear();
    workers_.reserve(sessions_.size());
    paused_.store(false);
    running_.store(true);

    try {
        for (const auto& session : sessions_) {
            auto* const active_session = session.get();
            workers_.emplace_back(
                [this, active_session, on_packet, on_error] {
                    while (running_.load() &&
                           active_session->state() != capture_state::stopped) {
                        if (active_session->state() == capture_state::paused) {
                            std::this_thread::sleep_for(std::chrono::milliseconds{2});
                            continue;
                        }
                        try {
                            auto packet = active_session->next_packet();
                            if (packet.has_value()) {
                                on_packet(interface_packet{
                                    active_session->interface_name(),
                                    std::move(packet.value()),
                                });
                            } else {
                                std::this_thread::sleep_for(std::chrono::milliseconds{1});
                            }
                        } catch (const std::exception& error) {
                            active_session->stop();
                            if (on_error) {
                                on_error(error.what());
                            }
                        }
                    }
                });
        }
    } catch (...) {
        running_.store(false);
        for (const auto& session : sessions_) {
            session->stop();
        }
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        workers_.clear();
        sessions_.clear();
        throw;
    }
}

void capture_runner::pause() noexcept {
    if (!running_.load()) {
        return;
    }
    for (const auto& session : sessions_) {
        session->pause();
    }
    paused_.store(true);
}

void capture_runner::resume() noexcept {
    if (!running_.load()) {
        return;
    }
    for (const auto& session : sessions_) {
        session->resume();
    }
    paused_.store(false);
}

void capture_runner::stop() noexcept {
    const std::lock_guard lock{lifecycle_mutex_};
    running_.store(false);
    paused_.store(false);
    for (const auto& session : sessions_) {
        session->stop();
    }
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
    sessions_.clear();
}

bool capture_runner::running() const noexcept {
    return running_.load();
}

bool capture_runner::paused() const noexcept {
    return paused_.load();
}

}  // namespace netscope::capture
