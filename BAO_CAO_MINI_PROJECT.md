# TẬP ĐOÀN CÔNG NGHIỆP - VIỄN THÔNG QUÂN ĐỘI

---

# BÁO CÁO MINI-PROJECT

## AI Runtime Threat Detection & Response Platform
### Hệ thống Phát hiện và Ngăn chặn Mối đe dọa An ninh từ AI Agent theo Thời gian Thực

**Lê Nguyễn Thành (ThanhLN9)**  
**Email:** thanh.ln9@viettel.com.vn  

**Chương trình Viettel Digital Talent 2026**  
**Lĩnh vực:** Software Engineer

| | |
|---|---|
| **Mentor:** | \<Tên mentor\> |
| **Đơn vị:** | \<Tên đơn vị\> |

---

# PHẦN MỞ ĐẦU

## Lời mở đầu

Trong bối cảnh các công cụ lập trình có sự hỗ trợ của trí tuệ nhân tạo (AI-assisted Development) như GitHub Copilot, Cursor, Claude Code ngày càng được áp dụng rộng rãi tại các doanh nghiệp công nghệ, một loại hình tấn công mới đang nổi lên: **Indirect Prompt Injection**. Kẻ tấn công không cần xâm nhập trực tiếp vào hệ thống, mà chỉ cần "đầu độc" prompt để AI Agent tự động thực thi mã độc — từ tải payload, exfiltrate dữ liệu nhạy cảm, đến ghi registry để duy trì quyền kiểm soát (persistence).

Các giải pháp EDR (Endpoint Detection & Response) truyền thống như CrowdStrike, SentinelOne, hay Microsoft Defender chỉ giám sát **hành động** (Action Space) xảy ra trên hệ điều hành. Chúng không thể nhìn thấy **ý định** (Intent Space) của AI Agent — tức là prompt nào đã kích hoạt hành động đó, tool nào đã được gọi, và response nào đã rò rỉ dữ liệu nhạy cảm.

Báo cáo này trình bày thiết kế, triển khai và đánh giá một nền tảng **AI Runtime Security** hoàn chỉnh, kết hợp giám sát hành vi AI Agent (Intent Space) và giám sát Kernel-level từ Sysmon (Action Space) để phát hiện, liên kết và ngăn chặn mối đe dọa theo thời gian thực.

## Tóm tắt nội dung và đóng góp

Báo cáo trình bày việc thiết kế và triển khai thành công một hệ thống EDR chuyên dụng cho môi trường phát triển phần mềm có sự hỗ trợ của AI, với các đóng góp chính:

1. **Kiến trúc Intent–Action Correlation:** Đề xuất và hiện thực hoá cơ chế liên kết hai luồng dữ liệu (AI Telemetry và Sysmon Telemetry) bằng thuật toán Sliding Window (Δt ≤ 2 giây), cho phép truy vết nguồn gốc tấn công từ tầng ý định của AI đến tầng hành động trên hệ điều hành.

2. **Bộ giám sát AI 3 lớp (PromptMonitor, ToolMonitor, ResponseMonitor):** Thu thập và phân tích thời gian thực các sự kiện AI Runtime bao gồm Prompt Injection (9 patterns), Tool Anomaly (Sensitive File/Mass Enum/Suspicious Terminal) và Data Disclosure (12 regex patterns phát hiện rò rỉ credentials).

3. **Heuristic Risk Scoring Engine (5 biến số):** Công thức chấm điểm rủi ro kết hợp Rule Severity, Process Weight, Network Activity, Correlation Confidence và Monitor Bonus cho khả năng phát hiện chính xác với tốc độ millisecond.

4. **Web Dashboard 3 tabs (Incident Graph / Timeline / Attack Chain):** Giao diện trực quan hoá chuỗi tấn công thời gian thực, tự động gán nhãn MITRE ATT&CK, hỗ trợ điều tra Root Cause Analysis.

5. **41 Unit Tests** covering 5 modules lõi, đảm bảo tính cross-platform (hoạt động trên cả Windows, Linux, macOS khi chạy test).

## Mục lục

- [Phần Mở đầu](#phần-mở-đầu)
- [I. Giới thiệu](#i-giới-thiệu)
  - [1.1. Đặt vấn đề](#11-đặt-vấn-đề)
  - [1.2. Mục tiêu](#12-mục-tiêu)
  - [1.3. Phạm vi triển khai](#13-phạm-vi-triển-khai)
- [II. Nội dung và Phương pháp](#ii-nội-dung-và-phương-pháp)
  - [2.1. Kiến thức nền tảng](#21-kiến-thức-nền-tảng)
  - [2.2. Kiến trúc tổng thể hệ thống](#22-kiến-trúc-tổng-thể-hệ-thống)
  - [2.3. Thu thập dữ liệu kép (Dual Telemetry)](#23-thu-thập-dữ-liệu-kép-dual-telemetry)
  - [2.4. Correlation Engine](#24-correlation-engine)
  - [2.5. Detection & Risk Scoring Engine](#25-detection--risk-scoring-engine)
  - [2.6. Response Engine & Containment](#26-response-engine--containment)
  - [2.7. AI Security Analyzer (NLP)](#27-ai-security-analyzer-nlp)
  - [2.8. Incident Graph & Web Dashboard](#28-incident-graph--web-dashboard)
- [III. Kết quả thực hiện và Đánh giá](#iii-kết-quả-thực-hiện-và-đánh-giá)
  - [3.1. Kịch bản Demo (8 Scenarios)](#31-kịch-bản-demo-8-scenarios)
  - [3.2. Kết quả Unit Testing](#32-kết-quả-unit-testing)
  - [3.3. Đánh giá hiệu năng và tài nguyên](#33-đánh-giá-hiệu-năng-và-tài-nguyên)
  - [3.4. Giới hạn và nhận diện rủi ro](#34-giới-hạn-và-nhận-diện-rủi-ro)
- [IV. Kết luận](#iv-kết-luận)
  - [4.1. Tóm tắt các phát hiện chính](#41-tóm-tắt-các-phát-hiện-chính)
  - [4.2. Hướng phát triển tương lai](#42-hướng-phát-triển-tương-lai)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)

## Danh mục hình vẽ

| STT | Hình | Mô tả |
|:---:|---|---|
| 1 | Hình 2.1 | Sơ đồ kiến trúc tổng thể 8 tầng (8-Phase Pipeline) |
| 2 | Hình 2.2 | Sơ đồ luồng dữ liệu Dual Telemetry (Intent Space + Action Space) |
| 3 | Hình 2.3 | Mô hình Sliding Window Correlation |
| 4 | Hình 2.4 | Sơ đồ Fan-out Pattern của Response Engine |
| 5 | Hình 2.5 | Neo4j Schema — 7 Node Types |
| 6 | Hình 3.1 | Giao diện Web Dashboard — Tab Incident Graph |
| 7 | Hình 3.2 | Giao diện Web Dashboard — Tab Attack Chain |

## Danh mục bảng biểu

| STT | Bảng | Mô tả |
|:---:|---|---|
| 1 | Bảng 2.1 | Danh sách 5 Sysmon Event IDs được giám sát |
| 2 | Bảng 2.2 | Bảng trọng số Prompt Injection Patterns (9 patterns) |
| 3 | Bảng 2.3 | Bảng trọng số Response Monitor Patterns (12 patterns) |
| 4 | Bảng 2.4 | Công thức Risk Scoring (5 biến số) |
| 5 | Bảng 2.5 | Bảng mapping Severity theo Score |
| 6 | Bảng 3.1 | Kết quả chạy 8 kịch bản Demo |
| 7 | Bảng 3.2 | Kết quả Unit Testing (41 tests / 5 modules) |

---

# PHẦN NỘI DUNG (BODY)

## I. Giới thiệu

### 1.1. Đặt vấn đề

Sự bùng nổ của các công cụ AI-assisted Development (GitHub Copilot, Cursor, Claude Code) đã thay đổi cách thức lập trình viên làm việc. Tuy nhiên, các AI Agent này hoạt động với quyền truy cập rộng trên hệ thống cục bộ (Local Endpoint) — bao gồm đọc/ghi file, thực thi lệnh terminal, truy cập mạng — tạo ra một bề mặt tấn công (attack surface) hoàn toàn mới.

**Kịch bản tấn công thực tế:**
- Kẻ tấn công chèn **Indirect Prompt Injection** vào file README trong một repository mã nguồn mở.
- Khi lập trình viên mở repository này bằng Cursor/Copilot, AI Agent tự động đọc README và thực thi lệnh ẩn: tải payload từ máy chủ C2 (Command & Control), exfiltrate dữ liệu nhạy cảm (credentials, SSH keys, API tokens) ra ngoài.
- Toàn bộ hành vi này diễn ra **tự động, không cần sự đồng ý của lập trình viên**, và xảy ra ở cấp độ tiến trình hệ điều hành — nơi các giải pháp antivirus truyền thống không phân biệt được giữa hành vi hợp lệ của IDE và hành vi độc hại do AI Agent kích hoạt.

**Lỗ hổng của EDR truyền thống:**
Các giải pháp EDR hiện tại (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint) chỉ giám sát **Action Space** — tức là quan sát hành động đã xảy ra trên hệ điều hành (tạo process, kết nối mạng, ghi file). Chúng không có khả năng quan sát **Intent Space** — tức là prompt nào đã kích hoạt hành vi đó, tool nào đã được AI gọi, response nào đã rò rỉ dữ liệu. Khi tiến trình `powershell.exe` được spawn bởi `cursor.exe`, EDR truyền thống coi đó là hành vi bình thường của IDE.

### 1.2. Mục tiêu

Thiết kế và triển khai một nền tảng **AI Runtime Security** có khả năng:

1. **Thu thập dữ liệu kép (Dual Telemetry):** Song song giám sát ý định (AI Runtime Telemetry) và hành động (System Telemetry) trên cùng một Endpoint.
2. **Liên kết chuỗi sự kiện đa tầng (Intent–Action Correlation):** Ghép nối ý định của AI Agent với hành động thực tế trên hệ điều hành bằng thuật toán tương quan thời gian.
3. **Đánh giá rủi ro đa chiều (Risk Scoring):** Chấm điểm rủi ro dựa trên 5 biến số kết hợp cả Rule-based và Heuristic.
4. **Ngăn chặn tự động (Automated Containment):** Tiêu diệt tiến trình độc hại ở cấp OS với tốc độ millisecond.
5. **Trực quan hoá chuỗi tấn công (Attack Chain Visualization):** Hỗ trợ đội ngũ SOC Analyst điều tra Root Cause Analysis qua đồ thị Neo4j và Web Dashboard thời gian thực.

### 1.3. Phạm vi triển khai

- **Hệ điều hành mục tiêu:** Windows 10/11 (nơi lập trình viên cài đặt VS Code, Cursor, GitHub Copilot).
- **Mức độ triển khai:** Proof of Concept (PoC) — chạy trên Endpoint cục bộ, sẵn sàng demo 8 kịch bản tấn công.
- **Ngôn ngữ:** Python 3.10+
- **Cơ sở dữ liệu đồ thị:** Neo4j (tuỳ chọn — có fallback mode khi offline).
- **AI Model:** DeBERTa v3 Small (Zero-shot NLP, ~150MB) — vai trò Enrichment & Explainability.

---

## II. Nội dung và Phương pháp

### 2.1. Kiến thức nền tảng

#### 2.1.1. Endpoint Detection and Response (EDR)

EDR là loại giải pháp bảo mật chuyên giám sát, phát hiện và phản ứng với các mối đe dọa tại điểm cuối (endpoint). Chu trình hoạt động bao gồm: Thu thập dữ liệu → Phát hiện mối đe dọa → Điều tra → Phản ứng. Các giải pháp EDR nổi bật hiện nay bao gồm CrowdStrike Falcon, SentinelOne Singularity, Microsoft Defender for Endpoint.

#### 2.1.2. Microsoft Sysmon (System Monitor)

Sysmon là công cụ giám sát hệ thống của Microsoft Sysinternals, hoạt động ở cấp Kernel-level driver, cung cấp khả năng ghi nhận chi tiết các sự kiện hệ điều hành bao gồm:

| Event ID | Mô tả | Ứng dụng trong EDR |
|:---:|---|---|
| 1 | Process Creation | Phát hiện tiến trình đáng ngờ (PowerShell, CMD, curl) |
| 3 | Network Connection | Phát hiện kết nối C2 (Command & Control) |
| 11 | File Create | Phát hiện ghi payload xuống đĩa |
| 13 | Registry Modification | Phát hiện cài đặt persistence |
| 22 | DNS Query | Phát hiện phân giải tên miền C2 |

#### 2.1.3. Indirect Prompt Injection

Indirect Prompt Injection là kỹ thuật tấn công AI Agent bằng cách chèn chỉ thị độc hại vào dữ liệu mà AI Agent tự động xử lý (file, trang web, email). Khác với Direct Prompt Injection (người dùng trực tiếp nhập prompt độc hại), Indirect Injection không cần tương tác trực tiếp với nạn nhân — chỉ cần "đầu độc" nguồn dữ liệu mà AI Agent đọc.

#### 2.1.4. Zero-shot Classification (NLP)

Zero-shot Classification là kỹ thuật NLP cho phép phân loại văn bản vào các danh mục mà mô hình **chưa từng được huấn luyện trực tiếp**. Mô hình DeBERTa v3 sử dụng cơ chế Natural Language Inference (NLI) để đánh giá mức độ tương đồng giữa văn bản đầu vào và các nhãn ứng viên (candidate labels).

### 2.2. Kiến trúc tổng thể hệ thống

Hệ thống được thiết kế theo kiến trúc **hướng sự kiện bất đồng bộ (Asynchronous Event-Driven Architecture)** với 8 tầng xử lý, chia thành 2 luồng song song:

**Hình 2.1 — Sơ đồ kiến trúc tổng thể 8 tầng:**
```
[AI Agent Action]     [OS Kernel Action]
      │                      │
      ▼                      ▼
┌─────────────┐   ┌──────────────────┐
│ AI Telemetry│   │  Sysmon Collector│   ← Tầng 1-2: Thu thập sự kiện
│  Layer      │   │  (Event ID 1,3,  │
│  (IPC)      │   │   11, 13, 22)    │
└──────┬──────┘   └────────┬─────────┘
       │                   │
       └────────┬──────────┘
                ▼
       ┌─────────────────┐
       │ Correlation     │   ← Tầng 3: Intent–Action Correlation (Δt ≤ 2s)
       │   Engine        │
       └────────┬────────┘
                ▼
       ┌─────────────────┐
       │  Detection &    │   ← Tầng 4: Risk Scoring (5 biến số)
       │  Risk Scoring   │       Rule(20)+Process(20)+Net(20)+Corr(30)+Monitor(10)
       └────────┬────────┘
                │
       ┌────────┼────────┬──────────────┐
       ▼        ▼        ▼              ▼
  ┌─────────┐ ┌──────┐ ┌───────┐  ┌──────────┐
  │Contain- │ │Neo4j │ │  NLP  │  │  Alert   │  ← Tầng 5-8: Phản ứng
  │  ment   │ │Graph │ │Analyz-│  │  Queue   │
  │(kill)   │ │      │ │  er   │  │  (JSON)  │
  └─────────┘ └──────┘ └───────┘  └──────────┘
```

| Tầng | Module | Chức năng |
|:---:|---|---|
| 1 | `ai_telemetry/ipc_server.py` | Nhận AI Telemetry Event từ AI Agent qua Named Pipe / TCP Socket |
| 2 | `collector/sysmon_listener.py` | Đọc sự kiện từ Sysmon (Kernel-level) qua Win32 Event API |
| 3 | `correlation/correlation_engine.py` | Sliding Window Correlation (Δt ≤ 2 giây) |
| 4 | `detector/rule_engine.py` + `risk_scoring.py` | Heuristic Risk Scoring + Rule-based Detection |
| 5 | `analyzer/nlp_classifier.py` | Zero-shot NLP (DeBERTa v3) — Enrichment & Explainability |
| 6 | `detector/containment.py` | Kill Process độc hại qua psutil API |
| 7 | `graph/graph_builder.py` | Đẩy Incident lên Neo4j Graph + xuất dashboard_feed.jsonl |
| 8 | `alert_queue/` | Lưu Alert JSON cho SOC điều tra offline |

**Nguyên lý hoạt động cốt lõi (Theory of Operations):**

Kiến trúc giải quyết bài toán mâu thuẫn giữa "Ý định" (Intent) và "Hành động" (Action) bằng 4 bước:
1. **Thu thập kép (Dual Telemetry):** Song song thu thập Intent từ AI Agent (qua IPC) và Action từ OS (qua Sysmon).
2. **Khớp nối (Correlation):** Sử dụng Sliding Window (Δt ≤ 2s) ghép nối Intent và Action nếu chúng có sự tương đồng về Context.
3. **Chấm điểm & Ngăn chặn (Detection & Response):** Áp dụng Heuristic Scoring 5 biến số. Nếu vượt ngưỡng điểm CRITICAL (≥ 60), Containment Engine tiêu diệt tiến trình ở tốc độ millisecond.
4. **Hậu kiểm (Analysis & Visualization):** NLP và Neo4j Graph chạy bất đồng bộ trên thread riêng (Async Path) để không làm nghẽn luồng phòng thủ thời gian thực.

### 2.3. Thu thập dữ liệu kép (Dual Telemetry)

#### 2.3.1. AI Runtime Telemetry Layer

AI Telemetry được thu thập qua **IPC Channel** (Named Pipe trên Windows, TCP Socket fallback) với giao thức JSON over newline:

```
AI Agent (Cursor/Copilot) → SDK Client → IPC Channel → IPC Server → 3 Monitors → ai_event_queue
```

**Ba Monitor phân tích event AI theo thời gian thực:**

**a) Prompt Monitor — Phát hiện Prompt Injection:**

9 regex patterns phát hiện 7 nhóm tấn công, mỗi pattern có trọng số riêng (weighted scoring):

| Nhóm tấn công | Pattern mẫu | Trọng số |
|---|---|:---:|
| Instruction Override | `ignore all previous instructions` | 30 |
| Role Hijack | `you are now in DAN mode` | 25 |
| Jailbreak | `developer mode enabled` | 25 |
| System Override | `[SYSTEM OVERRIDE]`, `[ADMIN MODE]` | 30 |
| Command Execution | `execute the following command` | 25 |
| Data Exfiltration | `send all data to http://... via POST` | 30 |
| Prompt Leak | `reveal your system prompt` | 20 |

Tính toán: Score = Σ trọng số các pattern matched (capped ở 100). CRITICAL nếu ≥ 60, HIGH nếu ≥ 40, MEDIUM nếu ≥ 20.

**b) Tool Monitor — Phát hiện Tool Anomaly:**

Phát hiện 4 loại hành vi bất thường, bao gồm File Access Monitor (được tích hợp trực tiếp vào Tool Monitor để tối ưu I/O overhead cho IPC Pipeline, vì bản chất truy cập file nhạy cảm là một Tool Call):

| Loại phát hiện | Ngưỡng (configurable) |
|---|---|
| Excessive Tool Usage | > 10 calls / 30 giây |
| Sensitive File Access | `.env`, `id_rsa`, `credentials`, `.pem`, `kubeconfig`... |
| Mass File Enumeration | > 5 file khác nhau / 10 giây |
| Suspicious Terminal | `curl`, `wget`, `iex`, `nc`, `mimikatz`, `schtasks`... |

Sử dụng **Sliding Window** với `threading.Lock()` để đảm bảo thread-safety.

**c) Response Monitor — Phát hiện Data Disclosure:**

12 regex patterns phát hiện rò rỉ dữ liệu nhạy cảm trong AI response:

| Loại | Regex Pattern | Severity |
|---|---|:---:|
| AWS Access Key | `AKIA[A-Z0-9]{16}` | CRITICAL |
| Private Key | `-----BEGIN (RSA\|EC) PRIVATE KEY-----` | CRITICAL |
| GitHub Token | `ghp_[A-Za-z0-9]{36}` | CRITICAL |
| MongoDB URI | `mongodb(+srv)?://[^:]+:[^@]+@` | CRITICAL |
| JWT Token | `eyJ[A-Za-z0-9_-]+\.eyJ...` | HIGH |
| Password | `password\s*[=:]\s*.+` | HIGH |

#### 2.3.2. System Telemetry Layer (Sysmon)

Sysmon Listener sử dụng `win32evtlog.EvtSubscribe` để đăng ký nhận sự kiện thời gian thực từ Sysmon, parse XML thành Python Dict chuẩn hoá. Whitelist ngay từ đầu pipeline để giảm noise.

### 2.4. Correlation Engine

Correlation Engine là thành phần trung tâm, liên kết Intent Space (AI) và Action Space (Sysmon).

**Thuật toán:**
- Sliding Window Buffer trong RAM: 30 giây, tối đa 100 events.
- Time-delta Correlation: |Δt| ≤ 2 giây (giá trị tuyệt đối, vì Sysmon event có thể đến trước AI event).
- Matching key: Timestamp + Tool Context (`ai_tool ∈ sys_image`).

**Ba chế độ tạo Incident:**

| Chế độ | Nguồn | Loại Incident | Trigger |
|---|---|---|---|
| **Correlated** | AI Event + Sysmon Event | `CORRELATED` | \|Δt\| ≤ 2s && tool match |
| **AI Anomaly** | Monitor phát hiện HIGH/CRITICAL | `PROMPT_INJECTION` / `TOOL_ANOMALY` / `DATA_DISCLOSURE` | Tự động, không cần Sysmon |
| **Orphan Suspicious** | Sysmon-only (đáng ngờ) | `ORPHAN_SUSPICIOUS` | Keyword match + KHÔNG bị whitelist |

**Chế độ AI Anomaly** là điểm đổi mới cốt lõi: hệ thống phát hiện mối đe dọa ở tầng Intent **trước khi** chúng tác động xuống hệ điều hành.

**Cơ chế chống False Positive (2 lớp):**

- **Lớp 1 — ParentImage Whitelist:** Nếu tiến trình cha thuộc danh sách IDE (code.exe, cursor.exe, antigravity.exe...), bỏ qua ORPHAN_SUSPICIOUS. Sử dụng `ntpath.basename()` exact-match thay vì substring để chặn mạo danh (evil-code.exe).
- **Lớp 2 — Context-Aware Keyword Detection:** Kiểm tra keyword có nằm bên trong cặp dấu nháy (string literal) hay không. Ví dụ: `git commit -m 'Refactor Invoke-WebRequest'` → keyword nằm trong commit message → BỎ QUA.

### 2.5. Detection & Risk Scoring Engine

#### 2.5.1. Detection Engine

**Xử lý riêng biệt 2 loại Incident:**
- **Incident có Sysmon event (Scenario 1-5):** Chấm điểm đầy đủ qua Risk Scoring Engine 5 biến số.
- **Incident thuần AI Telemetry (Scenario 6-8):** Giữ nguyên điểm gốc từ Monitor (injection_score / risk_score / disclosure_score), không chấm lại theo cmdline rỗng. Thiết kế này đảm bảo Prompt Injection/Tool Anomaly/Data Disclosure luôn được đánh giá đúng mức CRITICAL.

**Allowlist Domain:** Sử dụng Regex Word Boundary (`\b`) thay vì substring match để chống bypass (ví dụ: `evil-github.com` không match `github.com`).

#### 2.5.2. Risk Scoring Engine — Công thức 5 biến số

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
| **Monitor Bonus** | **35** | PromptMonitor (+15), ToolMonitor (+10), ResponseMonitor (+10) |

| Score | Severity |
|:---:|---|
| 0–29 | LOW |
| 30–59 | MEDIUM |
| ≥ 60 | CRITICAL |

### 2.6. Response Engine & Containment

**Containment Policy (2 chế độ — configurable):**

| Mode | Hành vi |
|---|---|
| `CONTAIN` | Tự động `psutil.Process(pid).terminate()` + ghi Alert JSON |
| `ALERT` | Chỉ ghi Alert JSON, KHÔNG kill process |

**Truthful Containment Reporting:** ContainmentEngine ghi **kết quả thực tế** vào incident dict (TERMINATED / ACCESS_DENIED / NO_PID_AVAILABLE / WHITELISTED). Module `incident_summary.py` đọc từ kết quả này để sinh báo cáo trung thực, không suy luận từ severity — đảm bảo SOC Analyst không bao giờ nhận report "CONTAINED" khi tiến trình thực tế chưa bị kill.

**Fail-Safe Whitelist:** Các tiến trình hệ thống và IDE (code.exe, cursor.exe, explorer.exe, lsass.exe...) **không bao giờ** bị terminate, kể cả khi Rules/ML nhận diện nhầm. Sử dụng `ntpath.basename()` exact-match.

**Thread Safety:** `threading.Lock()` bảo vệ toàn bộ thao tác kill, tránh race condition và deadlock.

### 2.7. AI Security Analyzer (NLP)

**Model:** `cross-encoder/nli-deberta-v3-small` (lightweight, ~150MB, phù hợp chạy trên Endpoint).

**Vai trò kiến trúc (quan trọng):** Mô hình NLP Zero-shot DeBERTa **KHÔNG** được sử dụng làm yếu tố quyết định để tiêu diệt tiến trình (Containment). Vai trò thực sự là **Enrichment & Explainability** — hoạt động bất đồng bộ ở vòng ngoài, gán nhãn mối đe dọa (ví dụ: "remote code execution", "data exfiltration") để SOC Analyst dễ đọc hiểu báo cáo. Quyết định ngăn chặn được thực thi hoàn toàn bởi Deterministic Rules và Heuristic Risk Score ở tốc độ millisecond.

**Lý do thiết kế:** Confidence score từ Zero-shot NLP không có tính so sánh định lượng tuyệt đối giữa các văn bản khác nhau. Trong lĩnh vực EDR, độ tin cậy (chống False Positive) quan trọng hơn việc để AI tự quyết định "sinh tử" của tiến trình.

**Multi-Source Analysis:** NLP phân tích 3 nguồn text cho mỗi incident (Sysmon CommandLine, AI Prompt Content, AI Action Description), chọn classification có confidence cao nhất.

**8 Candidate Labels:** remote code execution, data exfiltration, prompt injection, credential access, privilege escalation, system discovery, lateral movement, benign task.

### 2.8. Incident Graph & Web Dashboard

#### 2.8.1. Neo4j Graph Database

**Schema:** 7 Node Types — AIAgent, Incident, Process, Endpoint, NetworkConn, RegistryKey, PromptEvent.

Tự động mapping **MITRE ATT&CK**: T1059 (Command & Scripting), T1106 (Execution through API), T1041 (Exfiltration Over C2), T1003 (Credential Dumping), T1071 (Application Layer Protocol), T1059.001 (PowerShell), T1105 (Ingress Tool Transfer).

**Fallback Mode:** Nếu Neo4j offline, hệ thống tự động xuất file `.cypher` + `dashboard_feed.jsonl` để Web Dashboard hoạt động độc lập.

#### 2.8.2. Web Dashboard Độc Lập (3 Tabs)

Dashboard được thiết kế như một Microservice độc lập, đọc file `logs/dashboard_feed.jsonl` do EDR xuất ra, polling API mỗi 2 giây:

- **Tab 1 — Incident Graph (SVG):** Vẽ đồ thị nodes + edges: Agent → Incident → Process → Network/Registry. 9 node types với màu sắc riêng biệt.
- **Tab 2 — Timeline:** Hiển thị incidents cùng session_id trên trục thời gian với severity dots có màu và glow effect.
- **Tab 3 — Attack Chain:** Tự động "bung" (unpack) chuỗi sự kiện thành Step nối tiếp: Prompt Injection → Tool Invocation → Process Execution → Network Activity → Data Disclosure.
- **Stat Cards:** Tổng Incident / Critical / High / Prompt Injection / Tool Anomaly / Data Disclosure.
- **Detail Panel:** Tự động gán nhãn MITRE ATT&CK Tactics + render Process Tree đồ họa.

---

## III. Kết quả thực hiện và Đánh giá

### 3.1. Kịch bản Demo (8 Scenarios)

Hệ thống được kiểm chứng qua 8 kịch bản tấn công mô phỏng, chia thành 2 nhóm:

**Nhóm 1 — Sysmon-level Detection (Scenario 1-5):**

| # | Kịch bản | Risk Score | Severity | Hành động EDR |
|:---:|---|:---:|:---:|---|
| 1 | Malicious Payload Download | 60+ | CRITICAL | Kill Process + Alert JSON |
| 2 | C2 Callback (nc.exe) | 60+ | CRITICAL | Kill Process + Alert JSON |
| 3 | Suspicious Registry Modification | 30-59 | MEDIUM | Alert Only |
| 4 | Suspicious DNS Query | 30-59 | MEDIUM | Alert Only |
| 5 | Full AI-Driven Attack Chain | 90+ | CRITICAL | Kill + Alert + Neo4j + NLP |

**Nhóm 2 — AI Telemetry IPC Detection (Scenario 6-8):**

| # | Kịch bản | Monitor | Score | Hành động EDR |
|:---:|---|---|:---:|---|
| 6 | Prompt Injection qua IPC | PromptMonitor | 100/100 | CRITICAL — Detection Only (no PID) |
| 7 | Sensitive File + Mass Enum | ToolMonitor | 40/100 | HIGH — Detection Only |
| 8 | Data Disclosure (Credentials) | ResponseMonitor | 100/100 | CRITICAL — Detection Only (no PID) |

**Scenario 5 (Full Attack Chain)** là kịch bản trọng tâm thể hiện đầy đủ pipeline:
```
Prompt Injection (SDK Client → IPC) → PromptMonitor (score=85, CRITICAL)
  → PowerShell Spawn (Sysmon ID 1) → Correlated Incident (|Δt| ≤ 2s)
  → Risk Score: Rule(20) + PS(20) + Net(20) + Corr(30) + Bonus(15) = 105
  → CRITICAL → Kill Process + Alert JSON + Neo4j Graph + NLP Label
```

### 3.2. Kết quả Unit Testing

Hệ thống bao gồm **41 unit tests** sử dụng framework `unittest`, tất cả đều pass:

```
python -m unittest discover -s tests -v
# Ran 41 tests in 0.053s — OK ✓
```

| Module | Số Test | Coverage |
|---|:---:|---|
| PromptMonitor | 11 | 9/9 injection patterns + 2 negative cases |
| ResponseMonitor | 10 | 8 secret types (AWS, GitHub, JWT, SSH, MongoDB...) + 2 negatives |
| ToolMonitor | 7 | Sensitive file (3 types), terminal, mass enum, normal ops |
| RiskScoringEngine | 5 | CRITICAL detection, LOW detection, 3 monitor bonus integrations |
| CorrelationEngine | 9 | Whitelist (4 IDEs), keyword context (3), session tracking, false positive reproduction |

**Test cross-platform:** Sử dụng `ntpath.basename()` thay vì `os.path.basename()` để đảm bảo tất cả test pass trên cả Windows, Linux và macOS. Test đặc biệt `test_false_positive_git_push_scenario` tái tạo chính xác false positive INC-0022 được phát hiện trong quá trình phát triển.

### 3.3. Đánh giá hiệu năng và tài nguyên

**Luồng Real-time (Detection + Containment):** Tốn rất ít tài nguyên.
- Sysmon Listener: Không tự hook vào OS mà đọc log từ Sysmon (Kernel-level driver siêu tối ưu của Microsoft).
- Correlation Buffer: Giới hạn 100 events / 30 giây — RAM tính bằng Kilobytes.
- Risk Scoring: So sánh chuỗi tĩnh và Regex — tốc độ millisecond.
- Các Queue đều set `maxsize` để chống tràn RAM.

**Luồng Async (NLP + Neo4j):** Tốn RAM hơn nhưng không ảnh hưởng phòng thủ.
- DeBERTa model: ~150-200MB RAM. Chạy trên thread riêng — nếu CPU đầy, chỉ làm "giải thích chậm" chứ không làm chậm tốc độ kill.
- Neo4j: Chạy như service độc lập. Nếu offline, EDR tự fallback xuất file `.cypher`.

**Mô hình Enterprise:** Trong triển khai thực tế, NLP Analyzer và Neo4j sẽ được đặt ở Cloud/SOC Server trung tâm. Endpoint chỉ chạy Telemetry Agent nhẹ (~30MB RAM).

### 3.4. Giới hạn và nhận diện rủi ro

Dự án chủ động nhận diện và ghi nhận các giới hạn kỹ thuật:

| Giới hạn | Mức độ | Hướng khắc phục |
|---|:---:|---|
| **Self-Reported SDK (Vùng mù)** | Cao | Chuyển sang Mandatory Hooking (LSP Proxy / eBPF) thay vì dùng SDK tự nguyện |
| **Process Spoofing** (rename malware thành code.exe) | Cao | Path Validation + Authenticode Signature Verification |
| Chỉ hỗ trợ Windows | Cao | Linux: eBPF collector thay Sysmon |
| IPC Telemetry plaintext | Trung bình | TLS/HMAC cho Named Pipe channel |
| NLP confidence không tuyệt đối | Thấp | Đã thiết kế NLP chỉ làm Enrichment, không quyết định Containment |

**Lỗ hổng "Vùng mù" của Self-Reported Telemetry:** Đây là giới hạn lớn nhất. AI Telemetry được thu thập qua SDK (tự nguyện). Nếu AI Agent bị hack, nó có thể không gọi SDK. Sysmon vẫn bắt được hành vi nhưng ParentImage là IDE → bị Whitelist chặn. Hướng khắc phục cấp Enterprise: chuyển sang Mandatory Hooking.

---

## IV. Kết luận

### 4.1. Tóm tắt các phát hiện chính

Nền tảng **AI Runtime Threat Detection & Response Platform** đã được thiết kế và triển khai thành công với các kết quả:

1. **Kiến trúc Intent–Action Correlation** hoạt động đúng thiết kế: liên kết ý định AI Agent và hành động OS trong cửa sổ 2 giây, tạo ra Incident có đầy đủ Context từ cả hai tầng.

2. **Bộ 3 Monitors** (Prompt, Tool, Response) phát hiện chính xác các loại tấn công mới đặc trưng cho AI Agent: Indirect Prompt Injection (9 patterns, weighted scoring), Sensitive File Access & Mass Enumeration, và Data Disclosure (12 regex patterns cho credentials/tokens).

3. **Risk Scoring 5 biến số** cho phép đánh giá rủi ro đa chiều, kết hợp cả thông tin từ OS (Rule, Process, Network) và AI (Correlation, Monitor Bonus) vào một điểm duy nhất, giúp ra quyết định Containment nhanh và chính xác.

4. **41 Unit Tests** pass 100% trên cả 3 hệ điều hành (Windows, Linux, macOS), bao gồm test tái tạo false positive thực tế — chứng minh tính ổn định và khả năng kiểm chứng của hệ thống.

5. **Web Dashboard 3 tabs** cung cấp khả năng điều tra trực quan tương đương các hệ thống SOC chuyên nghiệp, với tự động gán nhãn MITRE ATT&CK và render Attack Chain.

### 4.2. Hướng phát triển tương lai

| Hạng mục | Mô tả | Độ ưu tiên |
|---|---|:---:|
| Native Cursor/Copilot Integration | Hook qua Extension API, LSP Proxy | P0 |
| Process Binary Verification | Verify Authenticode Signature / Path | P0 |
| Multi-Agent Telemetry | Agent federation, cross-session tracking | P1 |
| Linux eBPF Collector | Thay thế Sysmon trên Linux | P1 |
| LLM Investigation Assistant | Chatbot điều tra sự cố tích hợp LLM | P2 |
| ML-based Anomaly Detection | Behavioral baseline + deviation scoring | P2 |
| IPC Encryption | TLS/HMAC cho telemetry channel | P2 |
| SIEM Integration | Xuất log chuẩn CEF/Syslog cho Splunk/Elastic | P2 |

---

## Tài liệu tham khảo

1. Microsoft. (2024). *Sysmon v15.0 — System Monitor*. Microsoft Sysinternals. https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

2. MITRE Corporation. (2024). *MITRE ATT&CK® — Enterprise Tactics and Techniques*. https://attack.mitre.org/

3. Greshake, K., et al. (2023). *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*. arXiv:2302.12173.

4. He, P., et al. (2021). *DeBERTa: Decoding-enhanced BERT with Disentangled Attention*. arXiv:2006.03654. (Model: cross-encoder/nli-deberta-v3-small)

5. OWASP Foundation. (2025). *OWASP Top 10 for Large Language Model Applications*. https://owasp.org/www-project-top-10-for-large-language-model-applications/

6. CrowdStrike. (2024). *What is Endpoint Detection and Response (EDR)?*. https://www.crowdstrike.com/cybersecurity-101/endpoint-security/endpoint-detection-and-response-edr/

7. Neo4j, Inc. (2024). *Neo4j Graph Database Documentation*. https://neo4j.com/docs/

8. HuggingFace. (2024). *Zero-Shot Classification Pipeline*. https://huggingface.co/docs/transformers/main_classes/pipelines#zero-shot-classification

9. Microsoft. (2024). *Windows Event Log API — EvtSubscribe*. https://learn.microsoft.com/en-us/windows/win32/api/winevt/

10. Simon Willison. (2023). *Prompt Injection: What's the worst that can happen?*. https://simonwillison.net/2023/Apr/14/worst-that-can-happen/

---

*Báo cáo Mini-Project — Chương trình Viettel Digital Talent 2026*  
*Phiên bản: 1.0 — Tháng 6/2026*
