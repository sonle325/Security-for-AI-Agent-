# Security for AI Agent — AI Runtime Threat Detection & Response Platform

Hệ thống **AI Runtime Security (EDR)** chuyên dụng bảo vệ môi trường lập trình có sự hỗ trợ của AI (AI-assisted Development Environment) khỏi các cuộc tấn công **Indirect Prompt Injection**, **Data Exfiltration** và các hành vi thực thi mã độc do AI Agent tự động sinh ra.

Dự án kết hợp: giám sát Kernel-level (Sysmon), lưu vết Đồ thị Tấn công (Neo4j), và phân tích ngữ nghĩa dòng lệnh bằng mô hình AI NLP (DeBERTa v3).

---

## Kiến trúc 8 Tầng (8-Phase Pipeline)

```
[AI Agent Action]     [OS Kernel Action]
      │                      │
      ▼                      ▼
┌─────────────┐   ┌──────────────────┐
│ AI Telemetry│   │  Sysmon Collector│   ← Thu thập sự kiện
│  Layer      │   │  (Event ID 1,3,11)│
└──────┬──────┘   └────────┬─────────┘
       │                   │
       └────────┬──────────┘
                ▼
       ┌─────────────────┐
       │ Correlation     │   ← Liên kết Intent–Action (Δt ≤ 2s)
       │   Engine        │
       └────────┬────────┘
                ▼
       ┌─────────────────┐
       │  Detection      │   ← Probabilistic Risk Scoring
       │   Engine        │       Base Severity × Confidence × Context
       └────────┬────────┘
                │
       ┌────────┼────────┬──────────────┐
       ▼        ▼        ▼              ▼
  ┌─────────┐ ┌──────┐ ┌───────┐  ┌──────────┐
  │Contain- │ │Neo4j │ │  NLP  │  │  Alert   │
  │  ment   │ │Graph │ │Analyz-│  │  Queue   │
  │(kill)   │ │      │ │  er   │  │  (JSON)  │
  └─────────┘ └──────┘ └───────┘  └──────────┘
```

| Tầng | Module | Chức năng |
|------|--------|-----------|
| 1 | `mcp_gateway/`, `lsp_sniffer/`, `ai_telemetry/` | Thu thập AI Telemetry qua 3 lớp (MCP Intercept, OS Sniffing, IPC) |
| 2 | `collector/sysmon_listener.py` | Đọc luồng sự kiện từ Sysmon (Kernel-level) |
| 3 | `correlation/correlation_engine.py` | Sliding Window Correlation (Δt ≤ 2 giây) |
| 4 | `detector/rule_engine.py` | Probabilistic Risk Scoring, phát hiện payload |
| 5 | `analyzer/nlp_classifier.py` | Zero-shot NLP (DeBERTa v3) phân loại mối đe dọa |
| 6 | `detector/containment.py` | Kill Process độc hại qua psutil API |
| 7 | `graph/graph_builder.py` | Đẩy Incident lên Neo4j Graph Database |
| 8 | `alert_queue/` | Lưu file JSON cho SOC điều tra offline |

### 2. Mô hình Kiến trúc
Hệ thống gồm **8 tầng (Layers)**, với sự thay đổi cốt lõi ở Tầng 1 để giải quyết bài toán "Vùng Mù" của AI Agent.

```
[ IDE / Code Editor ] <──(LSP Sniffer)──> [ AI Agent (Cursor, Copilot, ...) ]
                                                         │
                                                  (MCP Protocol)
                                                         │
                                                         ▼
[ MCP Server Thật ] <───────(MCP Security Gateway)───────┘
                                       │ (Intercept & Block)
                                       ▼
                         [ AI_Runtime_Security (EDR) ]
```

#### Tầng 1: AI Telemetry Collection (Giải quyết Vùng Mù)
Thu thập hành vi của AI Agent qua 3 luồng:
1. **MCP Security Gateway (MỚI - MANDATORY)**: Transparent proxy đứng giữa AI Agent và các MCP Server. Intercept toàn bộ giao thức JSON-RPC (Model Context Protocol), phân tích `tools/call` và `resources/read`. Block real-time các tool call nguy hiểm trước khi chúng được thực thi.
2. **LSP Sniffer (MỚI - PASSIVE)**: Giám sát ở tầng OS (process list, named pipes) quá trình giao tiếp giữa IDE và AI Extension. Phát hiện các child process do AI sinh ra (như spawn shell, tải file) mà không cần AI tự nguyện báo cáo.
3. **SDK Client (Fallback)**: Dành cho các AI Agent tự nguyện tích hợp qua Named Pipe hoặc TCP.

#### Tầng 2: OS/Sysmon Collector
Kiến trúc của dự án giải quyết bài toán mâu thuẫn giữa "Ý định" (Intent) và "Hành động" (Action):
1. **Thu thập kép (Dual Telemetry):** Hệ thống song song thu thập 2 luồng dữ liệu. Tầng AI Telemetry bắt lấy **Ý định** của AI Agent (Prompt, Tool Call, Response) thông qua IPC Channel. Tầng Sysmon bắt lấy **Hành động thực tế** diễn ra trên Hệ điều hành (Tạo Process, Kết nối mạng, Ghi Registry).
2. **Khớp nối (Correlation):** Nếu AI gọi một tool (VD: `terminal.execute`), và trong vòng 2 giây (Sliding Window), OS ghi nhận một Process được tạo ra với nội dung tương đồng, Correlation Engine sẽ ghép chúng lại thành một **Incident** hoàn chỉnh mang cả Context của AI lẫn OS.
3. **Chấm điểm & Ngăn chặn (Detection & Response):** Incident được chấm điểm xác suất (Probabilistic Risk = Base Severity × Confidence × Context Multiplier). Nếu vượt ngưỡng `CRITICAL`, EDR lập tức bóp cò (Containment) bằng cách Kill Process ngay ở cấp OS.
4. **Hậu kiểm (Analysis & Visualization):** Dữ liệu được đẩy bất đồng bộ cho mô hình NLP DeBERTa để giải thích ngôn ngữ tự nhiên (Explainability) và xuất ra luồng dữ liệu đồ thị (Web Dashboard) giúp SOC Analyst theo dõi chuỗi tấn công Attack Chain.

---

## 🚀 Hướng dẫn Cài đặt & Chạy Demo

### 1. Yêu cầu hệ thống
- Hệ điều hành: Windows (Bắt buộc, do sử dụng Sysmon và Named Pipe)
- Python 3.9+
- Sysmon v15+ (tải từ Sysinternals)
- Neo4j (Local hoặc AuraDB)

### 2. Cài đặt Sysmon
```cmd
sysmon64.exe -i sysmon_config.xml
```

### 3. Cài đặt Python Dependencies
```cmd
pip install -r requirements.txt
```

### 4. Cấu hình hệ thống
Copy file `config.yaml.example` thành `config.yaml` và cấu hình:
- Neo4j credentials
- HuggingFace/OpenAI Token
- Các ngưỡng Alert & Blocking
- Cấu hình MCP Gateway (`mode: INTERCEPT` hoặc `MONITOR`)

### 5. Chạy Hệ thống (EDR Engine)
Mở một terminal với quyền Administrator (để đọc Sysmon):
```cmd
python main.py
```

### 6. Chạy Kịch bản Tấn công (Attack Simulation)
Hệ thống đi kèm các script giả lập tấn công để kiểm thử:

**A. Demo MCP Gateway (Real-time Blocking)**
Mở terminal thứ hai và chạy:
```cmd
python attack_simulation\demo_mcp_attack.py
```
> Script này sẽ giả lập việc gửi các tool calls nguy hiểm qua MCP Protocol và bị chặn ngay lập tức bởi MCP Security Gateway mà không cần thực thi ở OS.

**B. Demo Full Attack Chain (Prompt -> Tool -> OS)**
```cmd
python attack_simulation\demo.py
```
(Hoặc chạy cụ thể `python attack_simulation\demo.py --scenario exfiltration`)

---

## Kiểm tra kết quả sau Demo

```powershell
# Xem file Alert JSON được sinh ra tự động
ls alert_queue/
cat alert_queue/INC-0001.json
```

### Giám sát qua Web Dashboard (http://localhost:8888)
Đừng quên mở trình duyệt để trải nghiệm tính năng điều tra trực quan của hệ thống:
#### Tầng 5: Graph Engine (Neo4j)
Mô hình hóa Incident thành đồ thị:
- **Node**: Session, AI Agent, Prompt, Sysmon Process, File, Network.
- **Edge**: `TRIGGERED`, `SPAWNED`, `ACCESSED`, `CONNECTED_TO`.
- Cung cấp cái nhìn trực quan về chuỗi tấn công (Attack Chain) xuyên suốt từ MCP Tool Call tới OS Process.
- **Tab 3 (Attack Chain):** Tự động "bung" (unpack) một Incident thành các bước tuần tự (`Prompt -> Tool -> Process -> Network -> Leak`).
- **Detail Panel:** Hiển thị tự động gán nhãn **MITRE ATT&CK** và render **Process Tree** đồ họa.

---

## Bảo Vệ Trước Các Câu Hỏi Phản Biện (Defense Architecture)
Dự án được thiết kế kèm theo các luồng lập luận kiến trúc chặt chẽ để trả lời phản biện:
1. **Lỗ hổng Substring Match & Dấu Nháy:** Sử dụng parser (`shlex.split(posix=False)`) và Exact Match (`os.path.basename`) để giảm thiểu false-positive và chặn mạo danh bề mặt (`evil-code.exe`). Tuy nhiên, để ngăn chặn triệt để kỹ thuật Process Spoofing (rename payload độc hại thành `code.exe`), hệ thống cần kết hợp thêm **Path Validation** hoặc **Authenticode Signature Verification** (Microsoft/Cursor) ở cấp độ Enterprise.
2. **Chống Local Spoofing & DoS:** Tất cả hàng đợi (Queue) đều cấu hình `maxsize` cùng với mã xác thực Token cho kênh IPC nhằm chặn các hành vi gửi fake event hoặc spam event làm tràn RAM.
3. **Vùng mù của Self-Reported SDK:** Chủ động ghi nhận việc AI Agent có thể từ chối gọi SDK nếu bị hack. Hướng giải quyết cấp Enterprise là sử dụng **Mandatory Hooking** (LSP proxy / eBPF) thay thế.
4. **Giới hạn của mô hình NLP:** Mô hình Zero-shot DeBERTa chỉ được định vị làm nhiệm vụ **Enrichment & Explainability** (chạy async giải thích sự cố), hoàn toàn **KHÔNG** tham gia vào việc ra quyết định Containment (tiêu diệt tiến trình). Việc ra quyết định thuộc về tập Deterministic Rules siêu tốc độ.

---

## Cấu trúc Thư mục

```
AI_Runtime_Security/
├── main.py                          # Điểm khởi động EDR Engine
├── web_dashboard.py                 # Standalone Web Dashboard Server
├── config.yaml                      # Cấu hình tập trung toàn hệ thống
├── config_loader.py                 # Đọc và map cấu hình
├── download_model.py                # Script tải AI Model (DeBERTa) vào cache
├── requirements.txt                 # Thư viện Python cần thiết
│
├── mcp_gateway/                     # Tầng 1 (Lớp 1): Transparent Proxy chặn/sửa MCP traffic
│   ├── gateway.py                   # MCP Proxy Server
│   ├── interceptor.py               # Security Analyzer cho tools/call
│   └── protocol.py                  # JSON-RPC 2.0 Parser
│
├── lsp_sniffer/                     # Tầng 1 (Lớp 2): OS-level Passive Monitor
│   └── sniffer.py                   # Giám sát Process & Named Pipes
│
├── ai_telemetry/                    # Tầng 1 (Lớp 3): Thu thập qua SDK/IPC
│   ├── ipc_server.py                # Nhận sự kiện từ AI Agent tự nguyện báo cáo
│   ├── deduplicator.py              # Loại bỏ log trùng lặp giữa 3 lớp
│   └── prompt_monitor.py            # (+ ToolMonitor, ResponseMonitor, EventNormalizer)
│
├── collector/                       # Tầng 2: Thu thập Sysmon
│   ├── sysmon_listener.py           # Subscribe Sysmon Event Log (kernel-level)
│   └── event_parser.py              # Parse XML Sysmon Event → Dict chuẩn hóa
│
├── correlation/                     # Tầng 3: Liên kết sự kiện
│   └── correlation_engine.py        # Sliding Window Correlation (Δt ≤ 2s)
│
├── detector/                        # Tầng 4 & 6: Phát hiện + Ngăn chặn
│   ├── rule_engine.py               # Phát hiện Rule-based, AI Anomaly
│   ├── risk_scoring.py              # Probabilistic Risk Scoring (Severity x Confidence x Context)
│   └── containment.py               # Kill Process qua psutil + Fail-Safe
│
├── analyzer/                        # Tầng 5: Phân tích NLP
│   ├── nlp_classifier.py            # Zero-shot DeBERTa v3 threat classification
│   └── incident_summary.py          # Tổng hợp báo cáo Incident
│
├── graph/                           # Tầng 7: Đồ thị điều tra (Neo4j/Web)
│   ├── graph_builder.py             # Đẩy Incident lên Neo4j & xuất logs/dashboard_feed.jsonl
│   ├── neo4j_loader.py              # Xây dựng Cypher Query
│   └── dashboard.html               # Frontend Web UI (3 tabs: Graph / Timeline / Chain)
│
├── alert_queue/                     # Lưu trữ JSON các vụ CRITICAL offline
├── reports/                         # Báo cáo tổng hợp sự cố (RPT-INC)
├── logs/                            # Thư mục chứa log & data feed
│   ├── dashboard_feed.jsonl         # Data stream cho Web Dashboard
│   └── edr_engine.log               # Log hệ thống EDR
│
└── attack_simulation/               # Công cụ Demo & Testing (8 kịch bản)
    ├── demo_runner.py               # Chạy kịch bản tự động
    └── DEMO_CHEATSHEET.md           # Hướng dẫn demo cho buổi báo cáo
```
