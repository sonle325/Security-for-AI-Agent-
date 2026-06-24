"""Đọc config.yaml, cache kết quả, cung cấp cho toàn bộ project."""

import os
import logging

logger = logging.getLogger("EDR.Config")

_config_cache = None


def load_config(config_path: str = None) -> dict:
    """Đọc config.yaml, trả về dict. Cache sau lần đầu."""
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    if config_path is None:
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")

    try:
        import yaml  # type: ignore
        with open(config_path, "r", encoding="utf-8") as f:
            _config_cache = yaml.safe_load(f) or {}
        logger.info("Loaded config from %s", config_path)
    except FileNotFoundError:
        logger.warning("Không tìm thấy %s — dùng giá trị mặc định.", config_path)
        _config_cache = {}
    except ImportError:
        logger.warning("pyyaml chưa cài — dùng giá trị mặc định.")
        _config_cache = {}
    except Exception as e:
        logger.warning("Lỗi đọc config: %s — dùng giá trị mặc định.", e)
        _config_cache = {}

    return _config_cache


def get(section: str, key: str = None, default=None):
    """Truy cập config: get("neo4j", "uri", "bolt://localhost:7687")."""
    cfg = load_config()
    section_data = cfg.get(section, {})
    if key is None:
        return section_data if section_data else default
    if isinstance(section_data, dict):
        return section_data.get(key, default)
    return default
