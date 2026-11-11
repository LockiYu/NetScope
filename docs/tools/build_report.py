from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "docs" / "NetScope_Experiment_1A_Report.docx"


def set_run_font(run, name="Arial Unicode MS", size=11, bold=False):
    run.font.name = name
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = RGBColor(0, 0, 0)
    fonts = run._element.get_or_add_rPr().get_or_add_rFonts()
    fonts.set(qn("w:ascii"), name)
    fonts.set(qn("w:hAnsi"), name)
    fonts.set(qn("w:eastAsia"), name)


def shade(cell, fill):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill)


def set_cell_margins(cell, top=100, start=120, bottom=100, end=120):
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    tc_mar = tc_pr.first_child_found_in("w:tcMar")
    if tc_mar is None:
        tc_mar = OxmlElement("w:tcMar")
        tc_pr.append(tc_mar)
    for margin, value in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = tc_mar.find(qn(f"w:{margin}"))
        if node is None:
            node = OxmlElement(f"w:{margin}")
            tc_mar.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def set_repeat_header(row):
    tr_pr = row._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    tr_pr.append(tbl_header)


def add_table(doc, headers, rows, widths=None):
    table = doc.add_table(rows=1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = "Table Grid"
    set_repeat_header(table.rows[0])
    for index, text in enumerate(headers):
        cell = table.rows[0].cells[index]
        shade(cell, "1F4E78")
        cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        paragraph = cell.paragraphs[0]
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = paragraph.add_run(text)
        set_run_font(run, size=10, bold=True)
        run.font.color.rgb = RGBColor(255, 255, 255)
        set_cell_margins(cell)
    for row_index, values in enumerate(rows):
        cells = table.add_row().cells
        for column, text in enumerate(values):
            cell = cells[column]
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            if row_index % 2 == 1:
                shade(cell, "EAF2F8")
            paragraph = cell.paragraphs[0]
            paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER if column == 0 else WD_ALIGN_PARAGRAPH.LEFT
            run = paragraph.add_run(str(text))
            set_run_font(run, size=9.5)
            set_cell_margins(cell)
    if widths:
        for row in table.rows:
            for index, width in enumerate(widths):
                row.cells[index].width = Inches(width)
    doc.add_paragraph()
    return table


def add_heading(doc, text, level=1):
    paragraph = doc.add_heading(text, level=level)
    paragraph.paragraph_format.space_before = Pt(12 if level == 1 else 8)
    paragraph.paragraph_format.space_after = Pt(5)
    for run in paragraph.runs:
        set_run_font(run, size=16 if level == 1 else 13, bold=True)
    return paragraph


def add_body(doc, text, bold_lead=None):
    paragraph = doc.add_paragraph()
    paragraph.paragraph_format.first_line_indent = Inches(0.28)
    paragraph.paragraph_format.line_spacing = 1.25
    paragraph.paragraph_format.space_after = Pt(4)
    if bold_lead and text.startswith(bold_lead):
        lead = paragraph.add_run(bold_lead)
        set_run_font(lead, bold=True)
        rest = paragraph.add_run(text[len(bold_lead):])
        set_run_font(rest)
    else:
        run = paragraph.add_run(text)
        set_run_font(run)
    return paragraph


def add_bullet(doc, text):
    paragraph = doc.add_paragraph(style="List Bullet")
    paragraph.paragraph_format.left_indent = Inches(0.3)
    paragraph.paragraph_format.space_after = Pt(3)
    set_run_font(paragraph.add_run(text))


doc = Document()
section = doc.sections[0]
section.page_width = Inches(8.5)
section.page_height = Inches(11)
section.top_margin = Inches(0.65)
section.bottom_margin = Inches(0.65)
section.left_margin = Inches(0.78)
section.right_margin = Inches(0.78)

styles = doc.styles
normal = styles["Normal"]
normal.font.name = "Arial Unicode MS"
normal.font.size = Pt(11)
normal.paragraph_format.space_after = Pt(4)
normal._element.rPr.rFonts.set(qn("w:eastAsia"), "Arial Unicode MS")
for style_name in ("Title", "Subtitle", "Heading 1", "Heading 2", "Heading 3"):
    style = styles[style_name]
    style.font.name = "Arial Unicode MS"
    style.font.color.rgb = RGBColor(0, 0, 0)
    style._element.rPr.rFonts.set(qn("w:eastAsia"), "Arial Unicode MS")

title_style_ppr = styles["Title"]._element.get_or_add_pPr()
title_border = title_style_ppr.find(qn("w:pBdr"))
if title_border is not None:
    title_style_ppr.remove(title_border)

title = doc.add_paragraph(style="Title")
title.alignment = WD_ALIGN_PARAGRAPH.CENTER
title.paragraph_format.space_before = Pt(90)
title.paragraph_format.space_after = Pt(18)
set_run_font(title.add_run("NetScope 网络嗅探器设计与实现"), size=26, bold=True)

subtitle = doc.add_paragraph(style="Subtitle")
subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
subtitle.paragraph_format.space_after = Pt(36)
set_run_font(subtitle.add_run("软件与系统安全 实验 1A 技术报告"), size=16)

summary = doc.add_paragraph()
summary.alignment = WD_ALIGN_PARAGRAPH.CENTER
summary.paragraph_format.space_before = Pt(40)
summary.paragraph_format.line_spacing = 1.5
set_run_font(summary.add_run(
    "独立实现的 macOS 图形化 NPS 与 NPA\n"
    "C++17 · Qt 6 · libpcap\n"
    "2026 年 11 月"), size=13)

doc.add_page_break()

add_heading(doc, "摘要")
add_body(doc, "NetScope 是面向 macOS 的独立网络数据包嗅探与协议分析工具。软件直接调用 libpcap 从多个网络接口获取二层帧，不依赖 Wireshark 或 tshark；在用户态完成安全字节读取、分层协议解析、内核 BPF 抓包过滤、布尔显示过滤、TCP 流追踪、IP 分片重组、统计分析与异常观察。Qt 6 界面采用标准三窗格浏览器，将包列表、协议树与十六进制字节进行双向联动。项目满足实验对 GUI、NPS 和分层过滤的硬性要求，并实现了 TCP 流与时序图等加分功能。")
add_body(doc, "关键词：网络嗅探；libpcap；BPF；协议解析；TCP 流；Qt 6")

add_heading(doc, "1 实验目标与项目定位")
add_body(doc, "实验 1A 的核心是实现带图形界面的网络嗅探器，必须具备 NPS 能力，并尽量完善 NPA 能力。NetScope 的定位不是封装或调用 Wireshark，而是从抓包、解析、流状态到交互展示全链路独立实现。这一定位既能展示对 OSI 层次、内核抓包和协议状态的理解，也使每个安全边界和失败模式可被测试。")
add_table(doc, ["要求", "实现", "验收依据"], [
    ("GUI", "Qt 6 原生桌面界面，包列表、协议树、Hex 视图与可停靠分析面板", "离线 UI 集成测试"),
    ("NPS", "libpcap 实时抓包，支持多网卡、暂停、继续、停止和丢包统计", "后端会话与抓包运行器测试"),
    ("协议过滤", "内核 BPF 与应用层逻辑表达式两级过滤", "编译验证与过滤器单元测试"),
    ("TCP 流", "五元组归并、握手状态、重传、乱序、RTT、双向重组和时序图", "流追踪单元测试与界面测试"),
], widths=[1.1, 4.1, 1.6])

add_heading(doc, "2 系统架构")
add_body(doc, "项目采用分层架构，核心库不依赖 Qt Widgets，因而协议解析、重组和过滤可在无 GUI 环境下独立测试。界面层只负责交互状态、模型映射和异步调度。")
add_table(doc, ["层次", "主要组件", "责任"], [
    ("采集层", "capture_session  capture_runner  packet_merger", "网卡枚举、BPF、多线程抓包、合并、去重与 PCAP I O"),
    ("解析层", "byte_view  packet_parser  application_parser", "边界检查的字节读取与分层协议树生成"),
    ("分析层", "display_filter  tcp_flow  ip_reassembly", "显示过滤、TCP 流状态、分片重组和包对比"),
    ("洞察层", "traffic_statistics  anomaly_detector  reverse_dns", "聚合统计、可解释观察和异步反向 DNS"),
    ("界面层", "main_window", "三窗格浏览、停靠面板、图表、导出和配置持久化"),
], widths=[1.0, 2.5, 3.3])

add_heading(doc, "3 数据包采集")
add_heading(doc, "3 1 多网卡与抓包生命周期", 2)
add_body(doc, "程序枚举 macOS 可见接口，识别活动、回环、无线和隧道属性。用户可同时选择多个接口，每个接口由独立会话读取，然后按时间戳合并。合并器对短时间窗内的同字节包去重，避免同一包被物理口与虚拟口重复展示。状态机支持 active、paused 和 stopped，停止时主动打断 pcap 读取并回收线程。")
add_heading(doc, "3 2 过滤、截断长度与代理边界", 2)
add_body(doc, "抓包截断长度可编辑，默认 262144 字节，即保留完整帧的实用上限。BPF 表达式在开始前编译，无效语法不会进入抓包状态。过滤历史和收藏提供补全。数据面使用 libpcap 直接读取 BPF 设备，不经过 HTTP HTTPS SOCKS 代理；反向 DNS 仅调用系统解析器，遵循 macOS 默认网络路径。")

add_heading(doc, "4 协议解析与数据模型")
add_body(doc, "解析器使用不拥有内存的 byte view 和显式大端读取函数。每次读取前都验证偏移与长度，截断包产生警告而不越界。解析结果是递归 protocol node，字段同时保存原始值、显示值、字节范围、校验状态和警告，因此同一模型可支撑树形展示、Hex 反向定位、JSON 导出与异常检测。")
add_table(doc, ["层次", "已实现协议或元数据", "关键处理"], [
    ("L2", "Ethernet II  802 1Q  QinQ  ARP", "叠加 VLAN 、MAC 与 ARP 字段"),
    ("L3", "IPv4  IPv6  ICMP  ICMPv6", "IPv4 选项、IPv6 扩展头、校验和分片"),
    ("L4", "TCP  UDP", "端口、序列号、标志、选项与校验结果"),
    ("L7", "DNS  DHCP  HTTP  TLS", "DNS 名称压缩、DHCP 选项、HTTP 起始行与头名、TLS SNI ALPN"),
], widths=[0.8, 2.7, 3.3])

add_heading(doc, "5 过滤与交互分析")
add_body(doc, "显示过滤器与抓包 BPF 分离。它支持 and、or、not、括号、协议存在判断，以及 ip src、ip dst、tcp port、udp port 等字段比较。应用显示过滤只隐藏行，不删除内存数据，因此清空表达式即可恢复完整会话。")
add_body(doc, "包列表显示绝对本地时间、多网卡来源、地址、端口、协议、长度和摘要。列可排序、拖动、隐藏和调宽，布局会自动持久化。反向 DNS 在后台线程查询，界面仍保留原始 IP 供排序与过滤。用户还可标记数据包、添加备注、复制整行或从右键菜单生成过滤条件。")

add_heading(doc, "6 流追踪、重组与时序图")
add_heading(doc, "6 1 TCP 流", 2)
add_body(doc, "TCP 跟踪器将正反方向五元组规一化为同一流，根据 SYN、ACK、FIN 和 RST 维护 opening、established、half closed、closed 和 reset 状态。它以 TCP 序列号存储片段，可恢复乱序数据，计数重传和重复 ACK，并从 SYN 与 SYN ACK 估算 RTT。界面提供双向可打印数据、累积字节时序图和单流 PCAP 导出。")
add_heading(doc, "6 2 IP 分片", 2)
add_body(doc, "IPv4 使用源地址、目的地址、Identification 和上层协议建立重组键；IPv6 使用 Fragment 扩展头的 32 位 Identification。重组器接受乱序到达，以字节覆盖图判断缺口，遵循先到字节优先并记录重叠数量。收到尾片且零到终点无缺口时产生完整载荷，并在观察面板记录片数、长度和重叠字节。")

add_heading(doc, "7 统计、观察与导出")
add_body(doc, "统计面板实时维护总包数、总字节、包速率、字节速率、协议分布、高频主机、高频端口和长度分桶。观察面板不宣称已证明攻击，而是输出规则名、观察结论、证据和关联包或流。目前包括畸形包、明文认证头名、端口扫描倾向、高重传比和 IP 分片重组，其端口阈值、时间窗、最小流包数和重传比可调。")
add_table(doc, ["导出类型", "范围", "用途"], [
    ("PCAP", "全会话", "保留原始捕获长度和时间戳"),
    ("PCAP", "当前显示过滤结果", "导出调查子集"),
    ("PCAP", "单个 TCP 流", "在其他工具中复核流"),
    ("JSON", "选中包的协议树", "结构化审计或二次处理"),
    ("对比视图", "两个数据包", "按字段路径展示变化与缺失"),
], widths=[1.0, 2.6, 3.2])

add_heading(doc, "8 安全性与稳健性")
add_bullet(doc, "所有网络字节读取使用显式边界检查，不对未对齐内存做类型强转。")
add_bullet(doc, "协议解析对截断、无效长度、过多 IPv6 扩展头和异常分片进行有界退出。")
add_bullet(doc, "抓包线程不操作 GUI，数据通过队列切换到 Qt 主线程；反向 DNS 同样异步执行。")
add_bullet(doc, "内存仓库有容量上限，分片待重组表有数量和数据报长度上限。")
add_bullet(doc, "HTTP Authorization 只报告字段名存在，不在观察面板回显凭据值。")
add_bullet(doc, "软件不尝试解密 HTTPS，仅显示可见 TLS 握手元数据，避免将元数据分析误表述为内容解密。")

add_heading(doc, "9 测试与验证")
add_body(doc, "项目采用测试驱动开发。单元测试使用手工构造的最小帧覆盖正常、截断、乱序、重传、重叠分片和非法过滤表达式。集成测试在 Qt offscreen 平台下验证三窗格、抓包控件、反向 DNS、流面板、统计图、观察、标记、导出与分片完成记录。")
add_table(doc, ["测试类别", "覆盖内容", "预期"], [
    ("构建与解析", "工具链、字节读取、协议树、校验和应用层元数据", "全部通过"),
    ("采集与存储", "PCAP、网卡、BPF、运行器、合并与仓库", "全部通过"),
    ("分析", "显示过滤、DNS、TCP 流、统计、观察、IP 重组和包对比", "全部通过"),
    ("GUI", "窗口结构、联动、控件、会话、图表与导出", "全部通过"),
    ("动态检查", "AddressSanitizer  UndefinedBehaviorSanitizer  ThreadSanitizer", "无报错"),
], widths=[1.2, 4.2, 1.4])

add_heading(doc, "10 macOS 构建与运行")
add_body(doc, "开发环境为 macOS，使用 Apple Clang 和 C++17。依赖包括 CMake 3 25 或更高版本、Ninja、Qt 6 Widgets Charts、libpcap 与 GoogleTest。推荐通过 Homebrew 安装依赖，然后执行以下命令。")
code = doc.add_paragraph()
code.paragraph_format.left_indent = Inches(0.35)
code.paragraph_format.space_before = Pt(4)
code.paragraph_format.space_after = Pt(10)
set_run_font(code.add_run(
    "brew install cmake ninja qt libpcap googletest\n"
    "cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release\n"
    "cmake --build build -j\n"
    "open build/NetScope.app"), name="Menlo", size=9.5)
add_body(doc, "macOS 默认保护 dev bpf 设备。持久方案是安装 Wireshark 发布包中的 ChmodBPF 启动守护程，它仅调整 BPF 设备组权限，NetScope 仍是独立实现且不调用 Wireshark。安装后重新登录，以普通用户运行。若无权限，界面会保留可读错误而不崩溃。")

add_heading(doc, "11 演示与验收建议")
add_table(doc, ["顺序", "操作", "展示要点"], [
    ("1", "选择物理网卡和 lo0，使用完整包长开始抓包", "多网卡、状态切换和绝对时间"),
    ("2", "访问 HTTP 站点并执行 DNS 查询", "DNS HTTP TCP UDP 颜色、元数据和反向 DNS"),
    ("3", "输入 BPF 与显示过滤表达式", "内核过滤与非破坏式显示过滤的区别"),
    ("4", "选择包树字段和 Hex 字节，搜索文本与解释整数", "双向范围联动和安全字节视图"),
    ("5", "查看 TCP 流、重组数据和时序图", "五元组流追踪、RTT、重传和导出"),
    ("6", "展示统计和观察面板，调整阈值", "可解释证据与可配置性"),
    ("7", "标记备注，对比两包，导出过滤 PCAP 与 JSON", "调查工作流的完整性"),
], widths=[0.55, 3.6, 3.05])

add_heading(doc, "12 局限与后续工作")
add_body(doc, "当前版本不解密 TLS 应用数据，不将套接字映射到 macOS 进程，也未以插件机制动态加载协议解析器。这些限制不影响实验的 NPS、分层过滤和 TCP 流要求。后续可增加 QUIC 初始包元数据、长时会话的磁盘流式存储、更精细的 IPv6 分片超时策略，以及基于 macOS Network Extension 的授权进程归属。")

add_heading(doc, "13 结论")
add_body(doc, "NetScope 已完成从 macOS 网络接口到图形化分析结果的完整闭环。它不依赖现有协议分析器，而是以可测试的安全字节解析为基础，将内核 BPF、多网卡采集、协议树、流重组、时序图、统计观察和调查导出整合为一个原生桌面工具。实现范围覆盖实验硬性要求和主要加分点，同时保留了清晰的安全边界和可扩展架构。")

for paragraph in doc.paragraphs:
    if paragraph.style.name == "Normal":
        for run in paragraph.runs:
            if run.font.size is None:
                set_run_font(run)

doc.core_properties.title = "NetScope 网络嗅探器设计与实现"
doc.core_properties.subject = "软件与系统安全实验 1A 技术报告"
doc.core_properties.author = "NetScope Project"
doc.core_properties.keywords = "libpcap, Qt, packet sniffer, protocol analyzer"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
doc.save(OUTPUT)
print(OUTPUT)
