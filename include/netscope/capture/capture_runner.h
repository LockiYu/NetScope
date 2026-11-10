#pragma once

#include "netscope/capture/live_capture.h"
#include "netscope/capture/packet_merger.h"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace netscope::capture {

class capture_runner final {
public:
    using opener = std::function<capture_session(const std::string&, const capture_options&)>;
    using packet_handler = std::function<void(interface_packet)>;
    using error_handler = std::function<void(const std::string&)>;

    explicit capture_runner(opener open = open_live_capture);
    ~capture_runner();

    capture_runner(const capture_runner&) = delete;
    capture_runner& operator=(const capture_runner&) = delete;
    capture_runner(capture_runner&&) = delete;
    capture_runner& operator=(capture_runner&&) = delete;

    void start(
        const std::vector<std::string>& interfaces,
        const capture_options& options,
        packet_handler on_packet,
        error_handler on_error = {});
    void pause() noexcept;
    void resume() noexcept;
    void stop() noexcept;

    [[nodiscard]] bool running() const noexcept;
    [[nodiscard]] bool paused() const noexcept;

private:
    opener open_;
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::mutex lifecycle_mutex_;
    std::vector<std::unique_ptr<capture_session>> sessions_;
    std::vector<std::thread> workers_;
};

}  // namespace netscope::capture
