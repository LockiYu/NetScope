# NetScope

NetScope is an independent macOS packet sniffer and protocol analyzer for UCAS Software and System Security Experiment 1A. It uses libpcap for capture and Qt 6 for the native desktop interface; it does not invoke Wireshark or tshark.

## Features

- Live capture from one or more interfaces with selectable snapshot length, pause, resume, stop, kernel BPF filtering, packet merge, and duplicate suppression.
- Standard three-pane packet browser with sortable, movable, hideable, resizable, and persistent columns.
- Ethernet II, stacked VLAN, ARP, IPv4, IPv6 extension headers, TCP, UDP, ICMP, ICMPv6, DNS, DHCP, HTTP metadata, and TLS ClientHello metadata parsing.
- Display-filter expressions with logical operators and field comparisons, reverse DNS, protocol colors, marks, notes, byte search, byte-range synchronization, and integer inspection.
- IPv4 and IPv6 fragment reassembly, TCP flow tracking and stream reassembly, RTT and retransmission metrics, timing charts, traffic statistics, explainable observations, and configurable thresholds.
- PCAP open/save, filtered-packet export, TCP-flow export, protocol-tree JSON export, and two-packet field comparison.

Capture uses libpcap directly at the data-link layer. It neither reads nor uses HTTP, HTTPS, or SOCKS proxy settings, so local proxy configuration cannot redirect captured traffic or application network access. Reverse DNS uses the operating system resolver and otherwise follows the machine's normal network configuration.

## Build on macOS

Requirements: a macOS release supported by the selected Qt 6 toolchain, Apple Clang with C++17, CMake 3.25+, Ninja, Qt 6.8+ with Charts, libpcap, and GoogleTest.

```sh
brew install cmake ninja qt libpcap googletest
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The application bundle is generated at `build/NetScope.app`.

## Capture permission

macOS protects `/dev/bpf*`. The recommended persistent setup is to install Wireshark's `ChmodBPF` launch daemon, which grants the logged-in user access to BPF devices. This only supplies device permissions; NetScope remains an independent implementation and does not call Wireshark. After installing the helper, sign out and back in, then start NetScope normally.

If opening an interface fails, verify that a `/dev/bpf*` device is readable by the current user. Loopback (`lo0`) is useful for a controlled local test. Tunnel and VPN interfaces are shown but excluded from the default selection; physical active interfaces are selected by default when available.

## Run and test

```sh
open build/NetScope.app
ctest --test-dir build --output-on-failure
```

Sanitizer builds:

```sh
cmake -S . -B build-sanitize -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DNETSCOPE_ENABLE_ASAN=ON -DNETSCOPE_ENABLE_UBSAN=ON
cmake --build build-sanitize -j
ctest --test-dir build-sanitize --output-on-failure

cmake -S . -B build-tsan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DNETSCOPE_ENABLE_TSAN=ON
cmake --build build-tsan -j
ctest --test-dir build-tsan --output-on-failure
```

Only capture traffic you are authorized to inspect. HTTPS payload decryption is intentionally out of scope; NetScope displays unencrypted protocol metadata such as TLS version, handshake type, SNI, and ALPN.
