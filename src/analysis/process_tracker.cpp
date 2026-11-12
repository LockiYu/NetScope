#include "netscope/analysis/process_tracker.h"

#include "netscope/packet/byte_reader.h"
#include "netscope/protocol/packet_parser.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <string>
#include <utility>

#if defined(__APPLE__)
#include <arpa/inet.h>
#include <libproc.h>
#include <netinet/in.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#endif

namespace netscope::analysis {
namespace {

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

const protocol::protocol_node* find_node(
    const protocol::protocol_node& node,
    const std::string& name) {
    if (node.name == name) {
        return &node;
    }
    for (const auto& child : node.children) {
        if (const auto* found = find_node(child, name); found != nullptr) {
            return found;
        }
    }
    return nullptr;
}

const protocol::protocol_field* find_field(
    const protocol::protocol_node& node,
    const std::string& name) {
    const auto found = std::find_if(
        node.fields.begin(), node.fields.end(), [&name](const auto& field) {
            return field.name == name;
        });
    return found == node.fields.end() ? nullptr : &*found;
}

std::string field_value(
    const protocol::protocol_node* node,
    const std::string& name) {
    if (node == nullptr) {
        return {};
    }
    const auto* value = find_field(*node, name);
    return value == nullptr ? std::string{} : value->display_value;
}

std::uint16_t parse_port(const std::string& text) {
    if (text.empty()) {
        return 0U;
    }
    const auto value = std::strtol(text.c_str(), nullptr, 10);
    if (value < 0 || value > 65535) {
        return 0U;
    }
    return static_cast<std::uint16_t>(value);
}

bool address_matches(const std::string& socket_address, const std::string& packet_address) {
    return socket_address == packet_address || socket_address == "0.0.0.0" ||
        socket_address == "::";
}

bool endpoint_matches(
    const process_socket& socket,
    const std::string& address,
    const std::uint16_t port,
    const std::string& remote_address,
    const std::uint16_t remote_port) {
    return address_matches(socket.local_address, address) &&
        socket.local_port == port &&
        (socket.remote_port == 0U ||
         (socket.remote_address == remote_address && socket.remote_port == remote_port));
}

}  // namespace

class process_tracker::implementation final {
public:
    explicit implementation(snapshot_provider provider)
        : provider_{std::move(provider)} {}

    snapshot_provider provider_;
    mutable std::mutex mutex_;
    std::vector<process_socket> sockets_;
};

process_tracker::process_tracker()
    : implementation_{std::make_unique<implementation>(list_local_sockets)} {}

process_tracker::process_tracker(snapshot_provider provider)
    : implementation_{
          std::make_unique<implementation>(provider ? std::move(provider) : list_local_sockets)} {}

process_tracker::~process_tracker() = default;

process_tracker::process_tracker(process_tracker&&) noexcept = default;

process_tracker& process_tracker::operator=(process_tracker&&) noexcept = default;

void process_tracker::refresh() {
    auto sockets = implementation_->provider_ ? implementation_->provider_()
                                              : std::vector<process_socket>{};
    ingest(std::move(sockets));
}

void process_tracker::ingest(std::vector<process_socket> sockets) {
    for (auto& socket : sockets) {
        socket.transport = lowercase(std::move(socket.transport));
    }
    const std::lock_guard lock{implementation_->mutex_};
    implementation_->sockets_ = std::move(sockets);
}

std::optional<packet::process_owner> process_tracker::lookup(
    const capture::captured_packet& packet) const {
    const auto analysis =
        protocol::parse_ethernet_frame(packet::byte_view{packet.bytes});
    const auto* const tcp = find_node(analysis, "Transmission Control Protocol");
    const auto* const udp = find_node(analysis, "User Datagram Protocol");
    const protocol::protocol_node* const transport = tcp != nullptr ? tcp : udp;
    if (transport == nullptr) {
        return std::nullopt;
    }
    const auto* const ipv4 = find_node(analysis, "Internet Protocol Version 4");
    const auto* const ipv6 = find_node(analysis, "Internet Protocol Version 6");
    const auto* const network = ipv4 != nullptr ? ipv4 : ipv6;
    if (network == nullptr) {
        return std::nullopt;
    }
    return lookup(
        tcp != nullptr ? std::string_view{"tcp"} : std::string_view{"udp"},
        field_value(network, "source_address"),
        parse_port(field_value(transport, "source_port")),
        field_value(network, "destination_address"),
        parse_port(field_value(transport, "destination_port")));
}

std::optional<packet::process_owner> process_tracker::lookup(
    const std::string_view transport,
    const std::string_view source,
    const std::uint16_t source_port,
    const std::string_view destination,
    const std::uint16_t destination_port) const {
    if (source_port == 0U && destination_port == 0U) {
        return std::nullopt;
    }
    const auto wanted = lowercase(std::string{transport});
    const auto source_address = std::string{source};
    const auto destination_address = std::string{destination};
    const auto owner_for = [](const process_socket& socket) {
        return packet::process_owner{socket.process_name, socket.pid};
    };

    const std::lock_guard lock{implementation_->mutex_};
    for (const auto& socket : implementation_->sockets_) {
        if (socket.transport != wanted || socket.remote_port == 0U) {
            continue;
        }
        if (endpoint_matches(
                socket,
                source_address,
                source_port,
                destination_address,
                destination_port) ||
            (socket.local_address == destination_address &&
             socket.local_port == destination_port &&
             socket.remote_address == source_address &&
             socket.remote_port == source_port)) {
            return owner_for(socket);
        }
    }
    for (const auto& socket : implementation_->sockets_) {
        if (socket.transport != wanted || socket.remote_port != 0U) {
            continue;
        }
        if (endpoint_matches(
                socket, source_address, source_port, destination_address, destination_port) ||
            (address_matches(socket.local_address, destination_address) &&
             socket.local_port == destination_port)) {
            return owner_for(socket);
        }
    }
    return std::nullopt;
}

std::vector<process_socket> process_tracker::sockets() const {
    const std::lock_guard lock{implementation_->mutex_};
    return implementation_->sockets_;
}

std::size_t process_tracker::socket_count() const {
    const std::lock_guard lock{implementation_->mutex_};
    return implementation_->sockets_.size();
}

void process_tracker::clear() {
    const std::lock_guard lock{implementation_->mutex_};
    implementation_->sockets_.clear();
}

std::vector<process_socket> list_local_sockets() {
#if defined(__APPLE__)
    const auto format_address = [](const int family, const void* address) {
        char buffer[INET6_ADDRSTRLEN]{};
        if (inet_ntop(family, address, buffer, sizeof(buffer)) == nullptr) {
            return std::string{};
        }
        return std::string{buffer};
    };

    std::vector<process_socket> sockets;
    int pid_count = proc_listallpids(nullptr, 0);
    if (pid_count <= 0) {
        return sockets;
    }
    std::vector<pid_t> pids(static_cast<std::size_t>(pid_count));
    pid_count = proc_listallpids(
        pids.data(),
        static_cast<int>(pids.size() * sizeof(pid_t)));
    if (pid_count <= 0) {
        return sockets;
    }
    pids.resize(static_cast<std::size_t>(pid_count));

    for (const pid_t pid : pids) {
        if (pid <= 0) {
            continue;
        }
        char process_name[PROC_PIDPATHINFO_MAXSIZE]{};
        proc_name(pid, process_name, static_cast<int>(sizeof(process_name)));

        const int fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (fd_bytes <= 0 ||
            static_cast<std::size_t>(fd_bytes) < sizeof(proc_fdinfo)) {
            continue;
        }
        std::vector<proc_fdinfo> descriptors(
            static_cast<std::size_t>(fd_bytes) / sizeof(proc_fdinfo));
        const int read_bytes = proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            descriptors.data(),
            fd_bytes);
        if (read_bytes <= 0) {
            continue;
        }
        descriptors.resize(
            std::min(
                descriptors.size(),
                static_cast<std::size_t>(read_bytes) / sizeof(proc_fdinfo)));

        for (const auto& descriptor : descriptors) {
            if (descriptor.proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }
            socket_fdinfo info{};
            const int info_bytes = proc_pidfdinfo(
                pid,
                descriptor.proc_fd,
                PROC_PIDFDSOCKETINFO,
                &info,
                static_cast<int>(sizeof(info)));
            if (info_bytes != static_cast<int>(sizeof(info))) {
                continue;
            }
            const auto& psi = info.psi;
            if (psi.soi_family != AF_INET && psi.soi_family != AF_INET6) {
                continue;
            }
            if (psi.soi_protocol != IPPROTO_TCP && psi.soi_protocol != IPPROTO_UDP) {
                continue;
            }
            const auto* const endpoints = psi.soi_protocol == IPPROTO_TCP
                ? &psi.soi_proto.pri_tcp.tcpsi_ini
                : &psi.soi_proto.pri_in;

            process_socket socket;
            socket.transport = psi.soi_protocol == IPPROTO_TCP ? "tcp" : "udp";
            socket.local_port = ntohs(
                static_cast<std::uint16_t>(endpoints->insi_lport));
            socket.remote_port = ntohs(
                static_cast<std::uint16_t>(endpoints->insi_fport));
            if (psi.soi_family == AF_INET) {
                socket.local_address = format_address(
                    AF_INET, &endpoints->insi_laddr.ina_46.i46a_addr4);
                socket.remote_address = format_address(
                    AF_INET, &endpoints->insi_faddr.ina_46.i46a_addr4);
            } else {
                socket.local_address = format_address(
                    AF_INET6, &endpoints->insi_laddr.ina_6);
                socket.remote_address = format_address(
                    AF_INET6, &endpoints->insi_faddr.ina_6);
            }
            if (socket.local_address.empty()) {
                continue;
            }
            socket.process_name = process_name;
            socket.pid = static_cast<std::int32_t>(pid);
            sockets.push_back(std::move(socket));
        }
    }
    return sockets;
#else
    return {};
#endif
}

}  // namespace netscope::analysis
