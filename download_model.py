import os
from transformers import pipeline # type: ignore

# Ép tải qua server Mirror của châu Á để chống nghẽn mạng quốc tế
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

print("=== CÔNG CỤ TẢI MODEL AI CHUYÊN DỤNG (Bản nâng cấp) ===")
print("Đang kết nối tới máy chủ HF Mirror Siêu tốc...")
print("Sử dụng model DeBERTa v3 Small (chỉ 150MB - tải cực nhanh)...")
print("Lưu ý: Không click chuột vào màn hình đen trong lúc tải.\n")

try:
    classifier = pipeline("zero-shot-classification", model="cross-encoder/nli-deberta-v3-small")
    print("\n[+] ĐÃ TẢI MODEL THẬT 100% VÀ LƯU VÀO CACHE THÀNH CÔNG!")
    print("Bây giờ bạn có thể chạy lại lệnh: python main.py")
except Exception as e:
    print(f"\n[-] Lỗi khi tải: {e}")
