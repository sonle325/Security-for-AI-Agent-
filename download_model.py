import os
import config_loader
from transformers import pipeline  # type: ignore

nlp_cfg = config_loader.get("nlp", default={})
hf_mirror = nlp_cfg.get("hf_mirror", "https://hf-mirror.com")
model_name = nlp_cfg.get("model_name", "cross-encoder/nli-deberta-v3-small")

os.environ["HF_ENDPOINT"] = hf_mirror

print(f"Đang tải model {model_name} từ {hf_mirror}...")
print("Không click chuột vào màn hình đen trong lúc tải.\n")

try:
    classifier = pipeline("zero-shot-classification", model=model_name)
    print("\n[+] Tải model thành công! Chạy lại: python main.py")
except Exception as e:
    print(f"\n[-] Lỗi khi tải: {e}")
