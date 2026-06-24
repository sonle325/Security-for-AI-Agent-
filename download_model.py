import os
from transformers import pipeline  # type: ignore

os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

print("Đang tải model DeBERTa v3 Small (~150MB) từ HF Mirror...")
print("Không click chuột vào màn hình đen trong lúc tải.\n")

try:
    classifier = pipeline("zero-shot-classification", model="cross-encoder/nli-deberta-v3-small")
    print("\n[+] Tải model thành công! Chạy lại: python main.py")
except Exception as e:
    print(f"\n[-] Lỗi khi tải: {e}")
