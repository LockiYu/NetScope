#include "netscope/capture/macos_bpf_access.h"

#include <QProcess>
#include <QString>
#include <QStringList>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>

#if defined(__APPLE__)
#include <grp.h>
#include <unistd.h>
#endif

namespace netscope::capture {

namespace {

std::string lowercase(std::string_view value) {
    std::string result{value};
    std::transform(
        result.begin(), result.end(), result.begin(),
        [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return result;
}

}  // namespace

bool is_macos_bpf_permission_error(const std::string_view message) noexcept {
    try {
        const auto normalized = lowercase(message);
        const bool mentions_bpf =
            normalized.find("bpf device") != std::string::npos ||
            normalized.find("capture on that device") != std::string::npos;
        const bool mentions_permission =
            normalized.find("permission denied") != std::string::npos ||
            normalized.find("don't have permission") != std::string::npos ||
            normalized.find("not permitted") != std::string::npos;
        return mentions_bpf && mentions_permission;
    } catch (...) {
        return false;
    }
}

temporary_bpf_access_result request_temporary_macos_bpf_access(
    const std::chrono::milliseconds watch_duration) {
#if defined(__APPLE__)
    const auto* const admin_group = ::getgrnam("admin");
    if (admin_group == nullptr) {
        return {false, "macOS admin group was not found"};
    }

    constexpr auto interval = std::chrono::milliseconds{20};
    const auto bounded_duration = std::clamp(
        watch_duration,
        std::chrono::milliseconds{1000},
        std::chrono::milliseconds{60000});
    const auto iterations = std::max<std::int64_t>(
        1, bounded_duration.count() / interval.count());
    const auto user_id = static_cast<qulonglong>(::getuid());
    const auto group_id = static_cast<qulonglong>(admin_group->gr_gid);

    const auto shell_command = QStringLiteral(
        "/usr/bin/nohup /bin/zsh -c 'for i in {1..%1}; do "
        "/usr/sbin/chown %2:%3 /dev/bpf* 2>/dev/null; "
        "/bin/chmod 660 /dev/bpf* 2>/dev/null; "
        "/bin/sleep 0.02; "
        "done' >/dev/null 2>&1 &")
        .arg(iterations)
        .arg(user_id)
        .arg(group_id);
    const auto apple_script = QStringLiteral(
        "do shell script \"%1\" with administrator privileges")
        .arg(shell_command);

    QProcess process;
    process.start(
        QStringLiteral("/usr/bin/osascript"),
        QStringList{QStringLiteral("-e"), apple_script});
    if (!process.waitForStarted(5000)) {
        return {
            false,
            "failed to start macOS authorization dialog: " +
                process.errorString().toStdString(),
        };
    }
    process.waitForFinished(-1);
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        auto detail = QString::fromUtf8(process.readAllStandardError()).trimmed();
        if (detail.isEmpty()) {
            detail = process.errorString();
        }
        return {false, detail.toStdString()};
    }
    return {true, {}};
#else
    static_cast<void>(watch_duration);
    return {false, "temporary BPF authorization is only available on macOS"};
#endif
}

}  // namespace netscope::capture
