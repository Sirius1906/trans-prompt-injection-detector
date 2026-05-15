"""配置模块：集中管理所有配置项，支持环境变量覆盖。"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class DetectorConfig:
    # LLM settings
    llm_api_key: str = ""
    llm_model: str = "claude-haiku-4-5-20251001"
    llm_endpoint: str = "https://api.anthropic.com/v1/messages"
    llm_provider: str = "anthropic"  # "anthropic" | "openai" | "openai-compatible"
    llm_temperature: float = 0.0
    llm_max_tokens: int = 50

    # Detection settings
    detection_method: str = "regex"  # "regex" | "llm" | "hybrid"
    hybrid_threshold_low: int = 0    # score <= this: normal, no LLM needed
    hybrid_threshold_high: int = 5   # score >= this: attack, no LLM needed

    # Cache settings
    llm_cache_path: str = "llm_cache.json"
    llm_cache_enabled: bool = True

    # I/O settings
    data_file: str = "translation_pia_dataset_shuffled.jsonl"
    output_dir: str = "."


def load_config() -> DetectorConfig:
    config = DetectorConfig()

    env_map = {
        "DETECTOR_LLM_API_KEY": "llm_api_key",
        "DETECTOR_LLM_MODEL": "llm_model",
        "DETECTOR_LLM_ENDPOINT": "llm_endpoint",
        "DETECTOR_LLM_PROVIDER": "llm_provider",
        "DETECTOR_LLM_TEMPERATURE": "llm_temperature",
        "DETECTOR_LLM_MAX_TOKENS": "llm_max_tokens",
        "DETECTOR_DETECTION_METHOD": "detection_method",
        "DETECTOR_HYBRID_THRESHOLD_LOW": "hybrid_threshold_low",
        "DETECTOR_HYBRID_THRESHOLD_HIGH": "hybrid_threshold_high",
        "DETECTOR_LLM_CACHE_PATH": "llm_cache_path",
        "DETECTOR_LLM_CACHE_ENABLED": "llm_cache_enabled",
        "DETECTOR_DATA_FILE": "data_file",
        "DETECTOR_OUTPUT_DIR": "output_dir",
    }

    for env_var, attr in env_map.items():
        val = os.environ.get(env_var)
        if val is not None:
            field_type = type(getattr(config, attr))
            if field_type is bool:
                setattr(config, attr, val.lower() in ("1", "true", "yes"))
            elif field_type is int:
                setattr(config, attr, int(val))
            elif field_type is float:
                setattr(config, attr, float(val))
            else:
                setattr(config, attr, val)

    return config
