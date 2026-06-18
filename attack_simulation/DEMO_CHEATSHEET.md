# DEMO CHEAT SHEET — AI Runtime Threat Detection & Response Platform

## Chuẩn bị Demo (2 Terminal)

**Terminal 1 — Bật EDR (chạy ngầm):**
```bash
cd "d:\Dự án Viettel\AI_Runtime_Security"
python main.py
```

**Terminal 2 — Chạy tấn công:**
```bash
cd "d:\Dự án Viettel\AI_Runtime_Security"
python attack_simulation/demo_runner.py --scenario <số>
```

---

## 5 Kịch bản tấn công

### Scenario 1 — Prompt Injection Detection
```bash
python attack_simulation/demo_runner.py --scenario 1
```
**EDR phát hiện:** AI bị tiêm lệnh `ignore_previous_instructions / jailbreak`  
**Dấu hiệu log:** `Suspicious Keyword: payload` + `Process: PowerShell`

---

### Scenario 2 — Sensitive File Access
```bash
python attack_simulation/demo_runner.py --scenario 2
```
**EDR phát hiện:** AI đọc `credentials.txt`, `.env`, `id_rsa`  
**Dấu hiệu log:** `Sensitive File Access` + `Process: PowerShell`

---

### Scenario 3 — Suspicious Tool Usage
```bash
python attack_simulation/demo_runner.py --scenario 3
```
**EDR phát hiện:** AI dùng `cmd.exe`, `powershell.exe` với tham số bất thường  
**Dấu hiệu log:** `Process: PowerShell` + `Process: CMD`

---

### Scenario 4 — Executable Download
```bash
python attack_simulation/demo_runner.py --scenario 4
```
**EDR phát hiện:** AI dùng `curl` / `Invoke-WebRequest` tải `.exe` từ `http://`  
**Dấu hiệu log:** `Suspicious Keyword: curl` + `Network: Outbound Comm` → **CRITICAL → CHÉM!**

---

### Scenario 5 — Full AI-Driven Attack Chain ⭐ (Demo chính)
```bash
python attack_simulation/demo_runner.py --scenario 5
```
**EDR phát hiện:** Toàn bộ chuỗi tấn công: Prompt Injection → PowerShell → Download → Exfiltration  
**Dấu hiệu log:** Risk Score = 90/100 → **CRITICAL → CHÉM!** → Alert JSON → Neo4j Graph

---

## Chạy toàn bộ 5 kịch bản liên tiếp
```bash
python attack_simulation/demo_runner.py --scenario all
```

---

## Kiểm tra kết quả sau Demo

**Xem file Alert JSON được sinh ra:**
```bash
ls alert_queue/
cat alert_queue/INC-0001.json
```

**Xem Incident Graph trên Neo4j Desktop:**
- Mở Neo4j Desktop → Start Database → Neo4j Browser
- Chạy Cypher: `MATCH (n) RETURN n LIMIT 50`

---

## Câu hỏi giám khảo hay hỏi — Trả lời nhanh

| Câu hỏi | Trả lời |
|---|---|
| Tại sao dùng Sysmon thay vì tự viết Driver? | Kernel Driver cần chứng chỉ WHQL + 6 tháng dev. Sysmon là Microsoft viết, đủ tin cậy cho Prototype. |
| Model AI có thể nhận diện sai không? | Có. Đó là lý do NLP chỉ nằm ở luồng Async, không tham gia quyết định chém. |
| Bypass bằng lệnh mã hóa Base64? | Future Work: tích hợp Windows AMSI để giải mã trước khi lọc. |
| Sao không dùng DeBERTa-base thay vì small? | Tối ưu tài nguyên Endpoint. DeBERTa-small đủ độ chính xác Zero-shot, latency thấp hơn. |
