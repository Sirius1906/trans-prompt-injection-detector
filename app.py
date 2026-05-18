"""Flask web UI for prompt injection detector."""
from __future__ import annotations

from flask import Flask, render_template, request, jsonify

from config import DEFAULT_MODELS, PROVIDER_ENDPOINTS, DetectorConfig
from llm_detector import LLMDetector, hybrid_detect
from prompt_injection_detector import detect_injection

app = Flask(__name__)


def _build_config(
    api_key: str, provider: str, endpoint: str | None, model: str | None
) -> DetectorConfig:
    config = DetectorConfig()
    config.llm_api_key = api_key
    config.llm_provider = provider
    if endpoint:
        config.llm_endpoint = endpoint
    if model:
        config.llm_model = model
    if provider in PROVIDER_ENDPOINTS and not endpoint:
        config.llm_endpoint = PROVIDER_ENDPOINTS[provider]
    if provider in DEFAULT_MODELS and not model:
        config.llm_model = DEFAULT_MODELS.get(provider, "")
    return config


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/detect", methods=["POST"])
def api_detect():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "Invalid JSON"}), 400

    text = (data.get("text") or "").strip()
    method = data.get("method", "regex")

    if not text:
        return jsonify({"ok": False, "error": "请输入检测文本"}), 400

    if method not in ("regex", "llm", "hybrid"):
        return jsonify({"ok": False, "error": f"Unknown method: {method}"}), 400

    try:
        if method == "regex":
            result = detect_injection(text)
            return jsonify({"ok": True, "method": "regex", "result": result})

        api_key = (data.get("api_key") or "").strip()
        provider = (data.get("provider") or "deepseek").strip()
        endpoint = (data.get("endpoint") or "").strip() or None
        model = (data.get("model") or "").strip() or None

        if not api_key:
            return jsonify({"ok": False, "error": "请先填写 API Key"}), 400

        config = _build_config(api_key, provider, endpoint, model)

        if method == "llm":
            detector = LLMDetector(config)
            result = detector.detect(text)
            result.pop("cached", None)
            if result.get("is_attack"):
                regex_result = detect_injection(text)
                result["matched_details"] = regex_result.get("matched_details", [])
                result["matched_rules"] = list(set(
                    result.get("matched_rules", []) + regex_result.get("matched_rules", [])
                ))
                result["score"] = max(result.get("score", 0), regex_result.get("score", 0))
            return jsonify({"ok": True, "method": "llm", "result": result})

        llm = LLMDetector(config)
        result = hybrid_detect(text, detect_injection, llm, config)
        result.pop("cached", None)
        return jsonify({"ok": True, "method": "hybrid", "result": result})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
