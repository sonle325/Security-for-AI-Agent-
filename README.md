# Security-for-AI-Agent

Hệ thống AI Runtime Security (EDR) bảo vệ môi trường lập trình có sự hỗ trợ của AI (AI-assisted Development Environment) khỏi các cuộc tấn công Indirect Prompt Injection.

## Tính năng (8 Phases)
1. **AI Telemetry Layer**: Giả lập/Bắt hành vi AI.
2. **Sysmon Collector**: Thu thập Log từ hệ điều hành Windows.
3. **Correlation Engine**: Nối sự kiện thời gian thực bằng Sliding Window.
4. **Detection Engine**: Phát hiện Payload độc hại.
5. **Containment Engine**: Tự động chém Process (psutil).
6. **Response Engine**: Quản lý Alert/Contain.
7. **Neo4j Graph**: Lưu vết tấn công thành đồ thị.
8. **AI Security Analyzer**: Phân loại tấn công Zero-shot (DeBERTa NLP).

## Hướng dẫn cài đặt
```bash
pip install -r requirements.txt
```

## Chạy hệ thống
```bash
python main.py
```
*(Cần chạy bằng quyền Administrator)*
