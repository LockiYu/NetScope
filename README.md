# NetScope

NetScope 是一款面向 macOS 的独立网络嗅探与协议分析工具。项目使用 libpcap 抓包，使用 Qt 6 构建原生桌面界面，不调用 Wireshark 或 tshark。可选的 extcap 桥接器可将 NetScope 的抓包能力接入 Wireshark，作为互操作扩展，不构成运行时依赖。

## 功能概览

- 支持从一个或多个网络接口实时抓包，可设置抓包长度，并支持暂停、继续、停止、内核 BPF 过滤、数据包归并与去重。
- 提供标准三窗格数据包浏览器，列支持排序、移动、隐藏、调整宽度和持久化。
- 解析 Ethernet II、堆叠 VLAN、ARP、IPv4、IPv6 扩展头、TCP、UDP、ICMP、ICMPv6、DNS、DHCP、HTTP 元数据和 TLS ClientHello 元数据。
- 支持带逻辑运算符和字段比较的显示过滤表达式，以及 DNS 反向解析、协议着色、标记、备注、字节搜索、字节范围联动和整数解释。
- 支持 IPv4/IPv6 分片重组、TCP 流跟踪与字节流重组、RTT 和重传指标、时序图、流量统计、可解释观察和可配置阈值。
- 支持实时抓包的进程归属：macOS `libproc` 将 TCP/UDP 五元组映射到所属进程，数据包和流视图可显示归属结果，并可按进程过滤流。显示过滤器同时支持 `process` 和 `proc` 字段。
- 支持 PCAP 打开与保存、过滤后数据包导出、TCP 流导出、协议树 JSON 导出和两个数据包的字段对比。
- 提供 Wireshark extcap 桥接器 `netscope-extcap`，可在 Wireshark 中列出本机全部网络接口、输出 pcapng，并以数据包注释的形式附加所属进程。

抓包数据面通过 libpcap 直接读取数据链路层数据，不读取、也不使用 HTTP、HTTPS 或 SOCKS 代理设置，因此本机代理不会改变抓取路径。DNS 反向解析调用操作系统解析器，并遵循本机默认网络配置。

进程归属依赖 macOS `libproc`，后台线程每 5 秒刷新一次映射。该功能只覆盖当前用户有权读取的进程，跳过受 SIP 保护的进程和其他用户的进程；仅对实时抓包生效，且不会将进程信息写入导出的 PCAP 或 JSON 文件。

## 在 macOS 上构建

环境要求：Qt 6 工具链支持的 macOS 版本、支持 C++17 的 Apple Clang、CMake 3.25 或更高版本、Ninja、Qt 6.8 或更高版本（含 Charts）、libpcap 和 GoogleTest。

```sh
brew install cmake ninja qt libpcap googletest
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

应用程序包生成在 `build/NetScope.app`。

如果 CMake 解析到与库文件不匹配的 GoogleTest 包，例如 `PATH` 中更靠前的旧 Anaconda 安装，可显式指定 Homebrew 包：

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DGTest_DIR="$(brew --prefix googletest)/lib/cmake/GTest"
```

可使用可选的文档工具以可复现的方式生成报告截图：

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DNETSCOPE_BUILD_DOCS_TOOLS=ON
cmake --build build -j
QT_QPA_PLATFORM=offscreen ./build/netscope_screenshots docs/figures
```

## Wireshark extcap 互操作桥

`build/netscope-extcap` 实现 Wireshark extcap 契约。它复用主程序的 libpcap 抓包路径，并输出 pcapng：包含一个节头块、一个接口描述块，以及每个数据包对应的增强数据包块。五元组命中本地进程时，块中会写入 `NetScope process: <name> (pid <pid>)` 注释，Wireshark 会在数据包注释面板中显示该信息。

```sh
cmake --build build -j
sh tools/extcap/install_extcap.sh
```

安装脚本会把可执行文件链接到 Wireshark 的个人 extcap 目录。脚本优先通过 `tshark -G folders` 检测目录，检测失败时使用 `~/.local/lib/wireshark/extcap`。重启 Wireshark 后，打开 **捕获 > 选项**，选择 `NetScope: <device>` 接口。接口配置支持抓包过滤器、抓包长度、进程名开关和进程映射刷新间隔。

桥接方向为 NetScope 到 Wireshark。NetScope 不链接 Wireshark，桥接器只负责把 NetScope 输出转换为 Wireshark 接口。进程归属的范围与主程序相同：只匹配当前用户可读的进程，每隔数秒刷新套接字映射，且不向导出的 PCAP 或 JSON 文件写入进程信息。

## 抓包权限

macOS 保护 `/dev/bpf*` 设备。NetScope 不需要 Wireshark 的权限辅助组件。首次抓包或多网卡抓包创建新的 BPF 设备时，NetScope 会识别权限错误并询问是否临时授权；确认后出现系统管理员认证窗口，认证成功后程序会自动覆盖启动期间动态创建的 BPF 设备并重试全部已选网卡。

该流程不安装守护进程，不创建开机启动项，也不会让整个 NetScope 以 root 身份运行。临时权限在设备重建或系统重启后失效，届时程序会在下一次抓包时再次按需询问。

如果系统认证窗口无法使用，仍可用下面的命令对当前已经存在的设备进行手动临时授权：

```sh
sudo chown "$USER":admin /dev/bpf*
sudo chmod 660 /dev/bpf*
```

手动命令只修改执行时已经存在的 BPF 设备。多网卡启动期间可能继续生成新设备，因此应优先使用 NetScope 内置的自动授权与重试流程。

如果打开网络接口失败，请检查当前用户是否可读取 `/dev/bpf*` 设备。回环接口 `lo0` 适合用于受控的本机测试。界面会显示隧道和 VPN 接口，但默认不选中；存在活动物理接口时，会默认选中它们。

## 抓包规模与兜底

长时间抓包或设备被系统降频（例如窗口在后台被 App Nap 限流）时，界面不会一次性处理积压，也不会无限占用内存：

- 界面事件循环每轮最多追加 1024 个包或耗时 8 ms，剩余包会让出事件循环后继续处理，窗口始终保持可响应。
- 捕获线程到界面的待处理队列上限为 50000 个包；溢出时丢弃最旧的包，并在状态栏提示丢弃数量。
- 界面保留的数据包上限默认 50000 个，可通过环境变量 `NETSCOPE_MAX_PACKETS` 调整（下限 100）。达到上限时自动停止抓包，并提示先导出再重新开始；打开超过上限的 PCAP 时只加载前 N 个包并提示跳过的数量。

这些限制针对的是界面的内存与响应性；抓包本身仍由 libpcap 完成。

## 运行与测试

```sh
open build/NetScope.app
ctest --test-dir build --output-on-failure
```

启用消毒器的构建方式：

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

请只抓取已获授权检查的流量。NetScope 的分析范围为未加密协议内容与可见的 TLS 握手元数据，包括 TLS 版本、握手类型、SNI 和 ALPN；不解密 HTTPS 应用数据。
