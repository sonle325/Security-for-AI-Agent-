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

## Khởi động EDR

**Bắt buộc chạy bằng quyền Administrator** (để đọc Sysmon Event Log và Kill Process):

```powershell
# Mở PowerShell as Administrator
python main.py
```

Khi thấy dòng sau, EDR đã sẵn sàng:
```
[AI Analyzer] [+] NLP Pipeline tải thành công!
[*] EDR Engine is FULLY OPERATIONAL (8/8 Phases).
[*] Chế độ BACKGROUND: Tự động đánh hơi và tiêu diệt mọi tiến trình độc hại!
```

---

## Demo Tấn công & Phòng thủ

Mở **Terminal thứ 2** (không cần Admin) và chạy script Demo:

```powershell
# Chạy toàn bộ 5 kịch bản tấn công liên tiếp
python attack_simulation/demo_runner.py --scenario all

# Hoặc chọn từng kịch bản cụ thể:
python attack_simulation/demo_runner.py --scenario 1   # Prompt Injection
python attack_simulation/demo_runner.py --scenario 2   # Sensitive File Exfiltration
python attack_simulation/demo_runner.py --scenario 3   # Suspicious Tool Usage
python attack_simulation/demo_runner.py --scenario 4   # Executable Download (C2 Callback)
python attack_simulation/demo_runner.py --scenario 5   # Full Attack Chain
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

# Xem Incident Graph (nếu Neo4j đang chạy)
# Mở Neo4j Browser → http://localhost:7474
# Chạy: MATCH (n) RETURN n LIMIT 50
```

---

## Cấu trúc Thư mục

```
AI_Runtime_Security/
├── main.py                          # Điểm khởi động, orchestrator chính
├── download_model.py                # Script tải AI Model vào cache
├── requirements.txt                 # Thư viện Python cần thiết
│
├── ai_telemetry/                    # Tầng 1: Thu thập AI Telemetry
│   ├── agent_logger.py              # Nhận sự kiện từ AI Agent (IPC Channel)
│   └── event_normalizer.py          # Chuẩn hóa sự kiện về schema thống nhất
│
├── collector/                       # Tầng 2: Thu thập Sysmon
│   ├── sysmon_listener.py           # Subscribe Sysmon Event Log (kernel-level)
│   └── event_parser.py              # Parse XML Sysmon Event → Dict chuẩn hóa
│
├── correlation/                     # Tầng 3: Liên kết sự kiện
│   └── correlation_engine.py        # Sliding Window Correlation (Δt ≤ 2s)
│
├── detector/                        # Tầng 4 & 6: Phát hiện + Ngăn chặn
│   ├── rule_engine.py               # Heuristic Risk Scoring (4 biến số)
│   └── containment.py               # Kill Process qua psutil
│
├── analyzer/                        # Tầng 5: Phân tích NLP
│   ├── nlp_classifier.py            # Zero-shot DeBERTa v3 threat classification
│   └── incident_summary.py          # Tổng hợp báo cáo Incident ra file JSON
│
├── graph/                           # Tầng 7: Đồ thị điều tra
│   ├── graph_builder.py             # Orchestrator đẩy Incident lên Neo4j
│   └── neo4j_loader.py             # Xây dựng & thực thi Cypher Query
│
├── alert_queue/                     # Tầng 8: Queue cảnh báo offline
│   └── INC-XXXX.json               # Mỗi Incident CRITICAL → 1 file JSON
│
├── reports/                         # Báo cáo tổng hợp sự cố (SOC)
│   └── RPT-INC-XXXX.json
│
└── attack_simulation/               # Công cụ Demo & Testing
    ├── demo_runner.py               # 5 kịch bản tấn công tự động
    └── DEMO_CHEATSHEET.md           # Cheat sheet cho buổi bảo vệ
```
