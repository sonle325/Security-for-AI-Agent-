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
       │  Detection      │   ← Risk Scoring (4 biến số)
       │   Engine        │       Rule(20) + Process(20) + Net(20) + Corr(30)
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
| 1 | `ai_telemetry/agent_logger.py` | Nhận AI Telemetry Event từ AI Agent qua IPC |
| 2 | `collector/sysmon_listener.py` | Đọc luồng sự kiện từ Sysmon (Kernel-level) |
| 3 | `correlation/correlation_engine.py` | Sliding Window Correlation (Δt ≤ 2 giây) |
| 4 | `detector/rule_engine.py` | Heuristic Risk Scoring, phát hiện payload |
| 5 | `analyzer/nlp_classifier.py` | Zero-shot NLP (DeBERTa v3) phân loại mối đe dọa |
| 6 | `detector/containment.py` | Kill Process độc hại qua psutil API |
| 7 | `graph/graph_builder.py` | Đẩy Incident lên Neo4j Graph Database |
| 8 | `alert_queue/` | Lưu file JSON cho SOC điều tra offline |

---

## Yêu cầu Hệ thống

### Bắt buộc: Cài Sysmon
```powershell
# Tải Sysmon từ Microsoft Sysinternals, giải nén rồi chạy:
Sysmon64.exe -accepteula -i
```

### Khuyên dùng: Neo4j Desktop
Tải tại [neo4j.com/download](https://neo4j.com/download/) → Tạo Local Database với password = `password` → Start.

---

## Cài đặt

```powershell
git clone https://github.com/sonle325/Security-for-AI-Agent-.git
cd Security-for-AI-Agent-
pip install -r requirements.txt

# (Khuyên dùng) Tải trước AI Model ~150MB vào cache
python download_model.py
```

---

## Khởi động EDR & Web Dashboard

Hệ thống giờ đây được thiết kế theo chuẩn Microservices, chia làm 2 phần:

**1. Bật EDR (Bắt buộc chạy bằng quyền Administrator)**
```powershell
# Mở PowerShell as Administrator
python main.py
```
EDR sẽ chạy ngầm không giao diện, tự động đánh hơi và tiêu diệt tiến trình độc hại!

**2. Bật Web Dashboard (Không cần Admin)**
Mở Terminal thứ 2 và chạy:
```powershell
python web_dashboard.py
```
Sau đó truy cập **http://localhost:8888** trên trình duyệt để theo dõi thời gian thực.

---

## Demo Tấn công & Phòng thủ

Mở **Terminal thứ 2** (không cần Admin) và chạy script Demo:

```powershell
# Chạy toàn bộ 8 kịch bản tấn công liên tiếp
python attack_simulation/demo_runner.py --scenario all

# Hoặc chọn từng kịch bản cụ thể:
python attack_simulation/demo_runner.py --scenario 1   # Malicious Payload Download
python attack_simulation/demo_runner.py --scenario 2   # C2 Callback (nc.exe)
python attack_simulation/demo_runner.py --scenario 3   # Suspicious Registry Modification
python attack_simulation/demo_runner.py --scenario 4   # Suspicious DNS Query
python attack_simulation/demo_runner.py --scenario 5   # Full AI-Driven Attack Chain
python attack_simulation/demo_runner.py --scenario 6   # Prompt Injection qua IPC
python attack_simulation/demo_runner.py --scenario 7   # Truy Cập File Nhạy Cảm + Mass Enum
python attack_simulation/demo_runner.py --scenario 8   # Rò Rỉ Dữ Liệu (Credentials/Tokens) qua AI Response
```

### Kết quả kỳ vọng ở Terminal EDR:
```
[CorrelationEngine] [!] PHÁT HIỆN TIẾN TRÌNH CHẠY NGẦM ĐÁNG NGỜ!
[DetectionEngine]   [!] CẢNH BÁO MỨC ĐỘ CRITICAL: INC-0001
   [!] Công thức: Rule(20) + Process(20) + Net(20) + Corr(0) = 60 điểm
[ResponseEngine]    [+] ĐÃ TIÊU DIỆT THÀNH CÔNG TIẾN TRÌNH ĐỘC HẠI!
[AI Analyzer]       [+] Threat Label: REMOTE CODE EXECUTION (Confidence: 97.1%)
```

---

## Kiểm tra kết quả sau Demo

```powershell
# Xem file Alert JSON được sinh ra tự động
ls alert_queue/
cat alert_queue/INC-0001.json
```

### Giám sát qua Web Dashboard (http://localhost:8888)
Đừng quên mở trình duyệt để trải nghiệm tính năng điều tra trực quan của hệ thống:
- **Tab 1 (Incident Graph):** Vẽ sơ đồ liên kết `Agent -> Incident -> Process -> Network/Registry`.
- **Tab 2 (Timeline):** Luồng thời gian thực của các sự kiện trong cùng một phiên.
- **Tab 3 (Attack Chain):** Tự động "bung" (unpack) một Incident thành các bước tuần tự (`Prompt -> Tool -> Process -> Network -> Leak`).
- **Detail Panel:** Hiển thị tự động gán nhãn **MITRE ATT&CK** và render **Process Tree** đồ họa.

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
├── ai_telemetry/                    # Tầng 1: Thu thập AI Telemetry
│   ├── ipc_server.py                # Nhận sự kiện từ AI Agent (IPC Channel)
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
│   ├── risk_scoring.py              # Heuristic Risk Scoring (5 biến số)
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
