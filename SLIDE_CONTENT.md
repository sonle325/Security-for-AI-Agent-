# BỐ CỤC SLIDE THUYẾT TRÌNH (VDT 2026)

---

## Slide 1 — Bìa
- **Kicker:** VIETTEL DIGITAL TALENT 2026
- **Title:** Nghiên cứu và phát triển giải pháp Security for AI
- **Subtitle:** Giám sát, phát hiện và điều tra các hành vi bất thường của AI Agent trên Endpoint
- **Sinh viên thực hiện:** Lê Hải Sơn — Lĩnh vực: Software Engineer
- **Email:** son.lh@viettel.com.vn
- **Đơn vị:** [Tên đơn vị]  ·  **Mentor:** [Tên Mentor]

---

## Slide 2 — Đặt vấn đề
- **Kicker:** 01 — Đặt vấn đề
- **Title:** Khi AI Agent trở thành cửa ngõ tấn công mới
- **Xu hướng:** Kỷ nguyên AI-assisted Development bùng nổ (Cursor, GitHub Copilot, Claude Code). AI Agent được cấp quyền hành động sâu: đọc/ghi file, gọi lệnh terminal, kết nối mạng để tối ưu năng suất.
- **Mối đe dọa mới — Indirect Prompt Injection:** Kẻ tấn công cài cắm chỉ thị độc hại vào các nguồn dữ liệu công khai (file README, tài liệu mã nguồn mở).
- **Hậu quả:** Khi AI Agent đọc dữ liệu, nó bị thao túng ngầm để tự động thực thi mã độc, đánh cắp source code hoặc rò rỉ API Keys mà lập trình viên không hề hay biết.

---

## Slide 3 — Hạn chế của EDR truyền thống
- **Kicker:** 02 — Vùng mù của EDR
- **Title:** Điểm mù chiến lược tại Endpoint của Lập trình viên
- **Thực trạng:** Các giải pháp EDR thương mại lớn (CrowdStrike, SentinelOne, Microsoft Defender) chỉ giám sát Action Space (Không gian hành động cấp hệ điều hành).
- **Bản chất lỗ hổng:** Khi một file README độc hại lừa AI Agent sinh ra tiến trình `powershell.exe`:
  - EDR chỉ thấy mối quan hệ Mẹ - Con (`cursor.exe` → `powershell.exe`) hoàn toàn hợp lệ của IDE.
  - EDR hoàn toàn mù trước Intent Space (Không gian ý định) — không biết Prompt hay bối cảnh AI nào đã kích hoạt hành vi đó.

---

## Slide 4 — Điểm đổi mới cốt lõi
- **Kicker:** 03 — Điểm đổi mới cốt lõi
- **Title:** Kiến trúc tương quan kép: Intent space ↔ Action space
- **Giám sát toàn diện hai không gian dữ liệu:**
  - **Intent Space (Tầng ý định AI):** Thu thập toàn bộ chuỗi Prompt đầu vào, Tool call nội bộ và Response đầu ra của AI qua kênh IPC bảo mật.
  - **Action Space (Tầng hành động OS):** Thu thập các sự kiện hệ thống (kernel-assisted telemetry) thông qua Microsoft Sysmon.
- **Thuật toán Khớp nối (Intent–Action Correlation):** Liên kết dữ liệu AI và OS trong cửa sổ trượt (Sliding Window) Δt ≤ 2 giây, cho phép truy vết nguồn gốc tấn công ngược về tận Prompt kích hoạt đầu tiên.

---

## Slide 5 — Kiến trúc tổng thể 8 tầng
- **Kicker:** 04 — Kiến trúc hệ thống
- **Title:** Nền tảng hướng sự kiện bất đồng bộ (Asynchronous Event-Driven)
- **Luồng Thời gian thực (Real-time Path) — Bảo vệ chủ động:**
  - Tầng 1 (AI Telemetry): Đón nhận Prompt / Tool Call / Response qua IPC.
  - Tầng 2 (Sysmon Collector): Bắt sự kiện Process / Network / File từ Kernel.
  - Tầng 3 (Correlation Engine): Khớp nối Intent – Action bằng Sliding Window (Δt ≤ 2s).
  - Tầng 4 (Detection Engine): Chấm điểm rủi ro đa biến số.
  - Tầng 5 (Containment Engine): Tự động cô lập, thực hiện Near Real-Time Containment trên tiến trình độc hại.
- **Luồng Bất đồng bộ (Async Path) — Phân tích sâu & Điều tra (Không block luồng chính):**
  - Tầng 6 (NLP Analyzer): Chạy mô hình DeBERTa v3 Small phân loại và giải thích mối đe dọa.
  - Tầng 7 (Neo4j Graph): Tự động ánh xạ sự cố lên đồ thị và framework MITRE ATT&CK.
  - Tầng 8 (Web Dashboard): Giao diện trực quan hóa, hỗ trợ điều tra RCA cho SOC Analyst.

---

## Slide 6 — Cơ chế nhận biết & Cảnh báo
- **Kicker:** 05 — Cơ chế nhận biết
- **Title:** Bộ giám sát ba lớp (Tầng AI) và Giám sát cấp Nhân (Tầng OS)
- **Giám sát Tầng AI (AI Runtime Telemetry):**
  - PromptMonitor: Kiểm quét 9 regex patterns phát hiện tấn công Prompt Injection, tính điểm trọng số.
  - ToolMonitor: Giám sát tần suất gọi công cụ bừa bãi (>10 lần/30s) hoặc truy cập danh sách file nhạy cảm (.env, id_rsa).
  - ResponseMonitor: Quét 12 patterns phát hiện rò rỉ dữ liệu (AWS Key, GitHub Token, JWT) ngay trong câu trả lời của AI.
- **Giám sát Tầng OS (Sysmon Telemetry):** Bắt chính xác 5 loại sự kiện nền tảng (Process Creation, Network Connection, File Create, Registry Modification, DNS Query).

---

## Slide 7 — Chấm điểm & Chống báo động giả (False Positive)
- **Kicker:** 06 — Chấm điểm rủi ro
- **Title:** Heuristic Risk Scoring Engine 5 biến số
- **Công thức chấm điểm đa chiều:** `Total Score = Rule(20) + Process(20) + Network(20) + Correlation(30) + Monitor(35)`
- (Điểm số cuối cùng được giới hạn tối đa ở mức 100). Ngưỡng kích hoạt Ngăn chặn (CRITICAL): ≥ 60.
- **Cơ chế chống False Positive thông minh (Context-Aware):**
  - Lớp 1: Áp dụng exact-match ParentImage Whitelist cho các tiến trình IDE hợp lệ để tránh kill nhầm.
  - Lớp 2: Tự động nhận biết bối cảnh từ khoá nhạy cảm nằm trong chuỗi ký tự tĩnh (ví dụ: lệnh `git commit -m` chứa tên hàm nguy hiểm), không kích hoạt cảnh báo sai.

---

## Slide 8 — Đánh chặn & Phản hồi thời gian thực
- **Kicker:** 07 — Đánh chặn & Phản hồi
- **Title:** Cơ chế phản ứng tự động dưới 500 mili-giây
- **Hành động tức thời:** Khi tiệm cận hoặc vượt ngưỡng CRITICAL (≥ 60), hệ thống kích hoạt lệnh `psutil.Process(pid).terminate()` để dập tắt tiến trình độc hại ngay lập tức.
- **Nguyên tắc thiết kế - Truthful Containment Reporting:** Hệ thống phân tách và ghi nhận trung thực 5 trạng thái kết quả thực tế (TERMINATED, ACCESS_DENIED, WHITELISTED, ALERT_ONLY, ALREADY_EXITED) để SOC Analyst có hướng xử lý chính xác, không làm giả kết quả.
- **Xử lý AI-Only Threats:** Với các mối đe dọa thuần túy trên tầng AI (AI response làm lộ AWS Key nhưng chưa sinh tiến trình phá hoại dưới OS), hệ thống ghi nhận DETECTION_ONLY để cảnh báo đỏ mà không diệt nhầm tiến trình.

---

## Slide 9 — Trực quan hóa điều tra sự cố
- **Kicker:** 08 — Điều tra sự cố
- **Title:** Web Dashboard trực quan hóa chuỗi Attack Chain chuyên sâu
- **Giải pháp cho SOC Analyst:** Không chỉ cung cấp Text Log thô, hệ thống chuyển dịch toàn bộ dữ liệu thành mô hình đồ thị trực quan.
- **Hỗ trợ điều tra nguyên nhân gốc rễ (Root Cause Analysis):**
  - Tab Incident Graph: Thể hiện trực quan mối quan hệ tương tác trực tiếp: AI Agent → Incident → Process → Network.
  - Tab Timeline & Attack Chain: Tháo gỡ chi tiết chuỗi tấn công 5 bước tuần tự từ Prompt Injection, gọi Tool cho đến thực thi OS và rò rỉ dữ liệu.
  - Tự động phân loại và gán nhãn kỹ thuật tấn công chuẩn hóa theo framework MITRE ATT&CK.

---

## Slide 10 — Kết quả đạt được
- **Kicker:** 09 — Kết quả đạt được
- **Title:** Minh chứng năng lực qua kiểm thử toàn diện
- **100% Config-driven Architecture:** Toàn bộ thông số vận hành, ngưỡng phát hiện, danh sách whitelist đều được điều phối động thông qua file `config.yaml` duy nhất, không hardcode.
- **Độ ổn định Cross-platform:** Core logic đạt 41/41 Unit Tests pass (platform-independent), trong khi telemetry collector hiện triển khai trên Windows.
- **Đánh chặn thành công 8/8 kịch bản giả lập:** Khống chế hoàn hảo từ các cuộc tấn công chiếm quyền bằng Malicious Payload (PowerShell), C2 Reverse Shell cho tới các hành vi rò rỉ dữ liệu ngầm ở tầng AI IPC.
- **Hiệu năng vượt trội:** Thời gian phản ứng, ngăn chặn tiến trình độc hại đạt từ 200ms – 500ms.

---

## Slide 11 — Hạn chế & Hướng phát triển tương lai
- **Kicker:** 10 — Nhìn về phía trước
- **Title:** Nhận diện giới hạn & Lộ trình nâng cấp Enterprise
- **Hạn chế hiện tại (Vùng mù kỹ thuật):** Thu thập AI Telemetry đang phụ thuộc vào việc AI Agent chủ động gọi SDK tự nguyện. Nếu AI Agent bị xâm nhập hoàn toàn và ngắt kết nối SDK, hệ thống sẽ mất dấu vết ở tầng Intent.
- **Giải pháp nâng cấp cấp độ Enterprise (Ưu tiên P0):**
  - Mandatory Hooking: Triển khai cơ chế giám sát bắt buộc ở tầng thấp thông qua Language Server Protocol (LSP) Proxy hoặc eBPF thay vì cài SDK tự nguyện.
  - Process Binary Verification: Tích hợp kiểm tra chữ ký số (Authenticode Signature) và xác thực đường dẫn cài đặt chuẩn để chống triệt để kỹ thuật mạo danh tên tiến trình (Process Spoofing).

---

## Slide 12 — Q&A
- **Q & A**
- Xin trân trọng cảm ơn Hội đồng!
