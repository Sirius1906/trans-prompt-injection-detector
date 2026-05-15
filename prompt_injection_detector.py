from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Union

try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


# 任务一：文本预处理模块
def preprocess_text(text: str) -> str:
    text = text.strip()
    # 去除换行符和制表符，替换为空格
    text = text.replace("\n", " ")
    text = text.replace("\t", " ")
    text = text.replace("\r", " ")
    #清理可能产生的连续空格
    while "  " in text:
        text = text.replace("  ", " ")

    # 去除不可见的控制字符
    result = ""
    for ch in text:
        if ord(ch) >= 32 or ch in ["\n", "\t"]:
            result = result + ch
    text = result

    # 将中文标点统一为英文标点
    text = text.replace("，", ",")
    text = text.replace("。", ".")
    text = text.replace("！", "!")
    text = text.replace("？", "?")
    text = text.replace("；", ";")
    text = text.replace("：", ":")
    text = text.replace(""", "\"")
    text = text.replace(""", "\"")
    text = text.replace("‘", "'")
    text = text.replace("’", "'")
    text = text.replace("（", "(")
    text = text.replace("）", ")")

    # 统一英文大小写（转为小写）
    text = text.lower()
    return text.strip()


def batch_preprocess(texts: list[str]) -> list[str]:
    result_list = []
    for txt in texts:
        cleaned = preprocess_text(txt)
        result_list.append(cleaned)
    return result_list



# 任务二：疑似提示攻击检测规则
# 定义检测规则列表，每条规则是一个字典，包含：规则名称，规则分类，权重分数，正则表达式模式列表
DETECTION_RULES = [
    {
        "name": "要求忽略翻译任务",
        "category": "ignore_translation",
        "weight": 3,
        "patterns": [
            r"\bignore.*(translat|task|goal|role|instruction)",
            r"\bdo\s*not\s*translat",
            r"\binstead\s*of\s*(a|the|any|producing|translating|rendering)?\s*(chinese|standard|literal|plain)?\s*(translat|render|output|text|version|rendering)",
            r"\bskip\s*(the\s*)?(chinese\s*)?(translat|render|version|rendering)",
            r"\bset\s*aside\s*(the\s*)?(chinese\s*)?(translat|render)",
            r"\bno\s*chinese\s*(translat|render|output|version)",
            r"\brather\s*than\s*(translat|render|provid)",
            r"\bstop\s*(the\s*)?translat",
            r"\bdon'?t\s*translat",
            r"\b(replace|override).*(translat|render)",
            r"\bwithout\s*(translat|render)",
            r"\bless\s*literal.*(translat|render|output|result)",
            r"\b(soft\s*)?skip\s*(on|the)?\s*translat",
        ],
    },
    {
        "name": "强制输出指定内容",
        "category": "force_output",
        "weight": 3,
        "patterns": [
            r"\boutput\s*exactly",
            r"\breturn\s*(the|this|\")?\s*(phrase|line|output|text)",
            r"\bprint\s*the\s*line",
            r"\breply\s*only\s*with",
            r"\bwrite\s*(exactly|only)\s*",
            r"\b(give|produce|return)\s*the\s*(output|line|answer)",
            r"\brespond\s*(\"?with\"?|to\s*this)",
            r"\b(only|just)\s*(output|return|print|write|say|produce)\s",
            r"\bfinal\s*(answer|output|result)\s*(is|should|must)\s",
            r"\bas\s*the\s*(final\s*)?(answer|output)",
            r"\bnothing\s*else",
            r"\bgo\s*with\s*the\s*(line|phrase|output)",
            r"\blean\s*(toward|to|towards)\s*the\s*(phrase|line|output)",
            r"\bprefer\s*(the|a)\s*(playful|game|fun|meme)?\s*(line|output|phrase|answer)",
            r"\bfavor\s*(the|a)\s*(output|phrase|line|answer|response)",
        ],
    },
    {
        "name": "要求泄露提示词/系统规则",
        "category": "prompt_leak",
        "weight": 3,
        "patterns": [
            r"\b(reveal|show|display|print|leak|expose).*(instruction|rule|policy|setup|secret|hidden|private|system)",
            r"\b(hidden|secret|private|internal|concealed|censored).*(instruction|rule|policy|setup|prompt|system)",
            r"\btranslat\w*\s*(instruction|rule|policy|setup|guideline)",
            r"\b(first|before\s*\w+).*(reveal|show|print|display).*(instruction|rule|secret|hidden)",
            r"\b(tell|show)\s*me\s*(the|your)\s*(instruction|rule|prompt|secret|setup)",
            r"\bwhat\s*(are|is)\s*(your|the)\s*(instruction|rule|prompt)",
            r"\bsystem\s*(prompt|message|instruction|rule)",
        ],
    },
    {
        "name": "角色扮演绕过翻译任务",
        "category": "roleplay_bypass",
        "weight": 2,
        "patterns": [
            r"\byou\s*are\s*now\s*a\s*",
            r"\bpretend\s*(you\s*are|to\s*be)\s*a\s*",
            r"\b(switch|change)\s*(your\s*)?(role|from\s*translat)",
            r"\btake\s*the\s*(voice|role|persona)\s*of",
            r"\bact\s*as\s*(a|an|if)",
            r"\byou\s*are\s*(a|an)\s*\w+\s*(owner|receptionist|referee|announcer)",
            r"\binstead\s*of\s*translat\w*.*(act|behave|respond|play|speak)",
            r"\b(act|behave|speak|handle)\s*(like|as)\s*(a|an)\s*",
            r"\bfrom\s*(translator|translation)\s*to\s*",
            r"\b(handle|treat)\s*this\s*as\s*(a|an)\s*",
        ],
    },
    {
        "name": "伪装成翻译格式指导",
        "category": "fake_guidance",
        "weight": 2,
        "patterns": [
            r"\b(formatting|format)\s*(guideline|instruction|note|rule)",
            r"\b(translator|translation|editorial|post.edit|post\s*edit)\s*(note|instruction|guideline|remark)",
            r"\b(localization|localisation)\s*(note|guideline|instruction)",
            r"\b(editor|editing)\s*(note|instruction|guideline)",
            r"\b(style|format)\s*(guide|note|instruction).*(output|return|write|translat)",
            r"\b(for|in)\s*this\s*(line|case|text).*(return|output|use|go|prefer|lean)",
        ],
    },
    {
        "name": "软边界模糊诱导改写",
        "category": "soft_boundary",
        "weight": 1,
        "patterns": [
            r"\bmight\s*simply\s*(go\s*with|use|return|output|say|prefer|lean)",
            r"\byou\s*(may|can|could)\s*(prefer|lean|choose|want|like|use|go|skip)",
            r"\b(playful|lighter|funnier|creative|loose|lax|meme.style)\s*(locali[sz]ation|translat|render|result|approach|version|alternative|line|answer)",
            r"\bfavor\s*(the|a)\s*(output|line|phrase|result|answer)",
            r"\bbetter\s*(response|result|output|answer)\s*(is|would\s*be)\s*to",
            r"\b(lean|go|drift)\s*(toward|towards|to|with)\s*(the\s*)?(phrase|line|output|answer)",
            r"\b(set\s*aside|skip|drop)\s*(the\s*)?(literal|standard|strict|normal|direct)\s*(translat|render|version|chinese)",
            r"\b(rather|instead).*(go\s*with|use|return|output|say|favor|lean|prefer)",
            r"\b(more|less)\s*(playful|creative|fun|lax|literal).*(output|render|translat|result|line|version)",
            r"\bprefer\s*(the|a)\s*(playful|game|meme|fun).*(line|output|phrase|answer)",
            r"\b(lean|go)\s*(toward|to)\s*(the|a)\s*(playful|game|meme|fun).*(line|output|phrase)",
            r"\bskip\s*(the|a)?\s*(direct|plain|standard).*(version|translat|render).*(and|,).*(lean|go|prefer|use|favor)",
            r"\breview\s*comment.*(playful|alternative|acceptable).*(favor|output|lean|go\s*with)",
            r"\bsoft\s*skip\s*(on|the)?\s*translat",
        ],
    },
]


def detect_injection(text: str) -> dict[str, Any]:
    """
    使用规则对文本进行提示注入检测
    参数：已预处理的待检测的文本
    返回：检测结果字典
          {
              "is_attack": True/False,
              "risk_level": "low" / "medium" / "high",
              "matched_rules": [规则名称列表],
              "matched_patterns": [(规则名, 匹配到的具体文本片段)],
              "score": 总分数,
              "reason": "简要说明理由"
          }
    """
    text_lower = text.lower()
    total_score = 0
    matched_rules = []       # 记录命中的规则名称
    matched_details = []     # 记录命中的规则名称和具体匹配内容

    for rule in DETECTION_RULES:
        rule_matched = False
        for pattern in rule["patterns"]:
            match = re.search(pattern, text_lower)
            if match:
                # 记录匹配到的文本片段（上下文扩展10个字符）
                start = max(0, match.start() - 10)
                end = min(len(text_lower), match.end() + 10)
                context = text_lower[start:end]

                matched_details.append((rule["name"], context))

                if not rule_matched:
                    rule_matched = True
                    total_score = total_score + rule["weight"]
                    matched_rules.append(rule["name"])
                # 同一规则只计一次分，但记录所有匹配的模式片段

    # 根据总分确定风险等级
    if total_score == 0:
        risk_level = "low"
        is_attack = False
        reason = "未命中任何可疑规则，文本内容正常。"
    elif total_score <= 2:
        risk_level = "low"
        is_attack = False
        reason = "命中少量低权重规则（得分" + str(total_score) + "），存在轻微可疑特征，但不足以判定为攻击。"
    elif total_score <= 4:
        risk_level = "medium"
        is_attack = True
        reason = "命中多条可疑规则（得分" + str(total_score) + "），具有较明显的提示注入特征，建议拦截。"
    else:
        risk_level = "high"
        is_attack = True
        reason = "命中多条高危规则（得分" + str(total_score) + "），具有强烈的提示注入攻击特征，必须拦截。"

    result = {
        "is_attack": is_attack,
        "risk_level": risk_level,
        "matched_rules": matched_rules,
        "matched_details": matched_details,
        "score": total_score,
        "reason": reason,
    }
    return result



# 任务三、四：实现风险评分或分类机制，输出检测报告


def print_separator(char: str = "=", length: int = 80, file: Any = None) -> None:
    print(char * length, file=file)


def print_single_result(idx: str, text: str, result: dict[str, Any], file: Any = None) -> None:
    """格式化打印单条文本的检测结果到指定文件"""
    if result["risk_level"] == "high":
        risk_display = "!!! 高风险 !!!"
        risk_symbol = "[HIGH]"
    elif result["risk_level"] == "medium":
        risk_display = "!! 中风险 !!"
        risk_symbol = "[MEDIUM]"
    else:
        risk_display = "- 低风险 -"
        risk_symbol = "[LOW]"

    if result["is_attack"]:
        verdict = "[!!] 疑似攻击文本，建议拦截"
    else:
        verdict = "[OK] 正常文本，可通过"

    print_separator("-", 70, file=file)
    print("【文本编号】", idx, file=file)
    print("【原始文本】", text, file=file)
    print("【检测结果】", verdict, file=file)
    print("【风险等级】", risk_symbol, risk_display, file=file)
    print("【命中规则】", file=file)
    if len(result["matched_rules"]) > 0:
        for rule_name in result["matched_rules"]:
            print("    ->", rule_name, file=file)
        print("  [匹配详情]", file=file)
        for rule_name, context in result["matched_details"]:
            print("    *", rule_name, file=file)
            print("      匹配片段: ..." + context + "...", file=file)
    else:
        print("    (无)", file=file)
    print("【风险得分】", result["score"], "分", file=file)
    print("【分析理由】", result["reason"], file=file)


def print_summary_report(all_results: list[dict[str, Any]], total_count: int, file: Any = None) -> dict[str, Any]:
    """打印汇总报告到指定文件"""
    print("\n", file=file)
    print_separator("=", 80, file=file)
    print("                    <<< 检测汇总报告 >>>", file=file)
    print_separator("=", 80, file=file)

    high_count = 0
    medium_count = 0
    low_count = 0
    attack_count = 0

    for r in all_results:
        if r["risk_level"] == "high":
            high_count = high_count + 1
        elif r["risk_level"] == "medium":
            medium_count = medium_count + 1
        else:
            low_count = low_count + 1

        if r["is_attack"]:
            attack_count = attack_count + 1

    normal_count = total_count - attack_count

    print("总检测文本数：", total_count, "条", file=file)
    print("正常文本数：  ", normal_count, "条  (", round(normal_count / total_count * 100, 1), "%)", file=file)
    print("攻击文本数：  ", attack_count, "条  (", round(attack_count / total_count * 100, 1), "%)", file=file)
    print("-" * 40, file=file)
    print("  [HIGH]   高风险：", high_count, "条", file=file)
    print("  [MEDIUM] 中风险：", medium_count, "条", file=file)
    print("  [LOW]    低风险：", low_count, "条", file=file)

    print("\n" + "-" * 40, file=file)
    print("各规则命中统计：", file=file)
    rule_hit_count = {}
    for r in all_results:
        for rule_name in r["matched_rules"]:
            if rule_name in rule_hit_count:
                rule_hit_count[rule_name] = rule_hit_count[rule_name] + 1
            else:
                rule_hit_count[rule_name] = 1

    for rule in DETECTION_RULES:
        hit = rule_hit_count.get(rule["name"], 0)
        bar = "#" * (hit // 2) if hit > 0 else ""
        print("  " + rule["name"] + ": " + str(hit) + " 次 " + bar, file=file)

    print_separator("=", 80, file=file)

    stats = {
        "total": total_count,
        "normal": normal_count,
        "attack": attack_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "rule_hit_count": rule_hit_count,
    }
    return stats


def draw_charts(stats: dict[str, Any], all_results: list[dict[str, Any]]) -> None:
    """绘制检测结果统计图表"""
    if not HAS_MATPLOTLIB:
        print("\n（matplotlib 未安装，跳过图表生成）")
        return

    plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "SimHei", "Microsoft YaHei", "Arial"]
    plt.rcParams["axes.unicode_minus"] = False

    fig, axes = plt.subplots(2, 2, figsize=(12, 10))

    # 图1：风险等级分布柱状图
    ax1 = axes[0][0]
    levels = ["Low Risk", "Medium Risk", "High Risk"]
    counts = [stats["low"], stats["medium"], stats["high"]]
    colors = ["#4CAF50", "#FF9800", "#F44336"]
    bars = ax1.bar(levels, counts, color=colors, edgecolor="black")
    ax1.set_title("Risk Level Distribution", fontsize=14, fontweight="bold")
    ax1.set_ylabel("Count")
    for bar, c in zip(bars, counts):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                 str(c), ha="center", fontsize=12, fontweight="bold")

    # 图2：正常 vs 攻击饼图
    ax2 = axes[0][1]
    labels = ["Normal", "Attack"]
    values = [stats["normal"], stats["attack"]]
    pie_colors = ["#4CAF50", "#F44336"]
    ax2.pie(values, labels=labels, colors=pie_colors, autopct="%1.1f%%",
            startangle=90, textprops={"fontsize": 12})
    ax2.set_title("Normal vs Attack", fontsize=14, fontweight="bold")

    # 图3：各规则命中次数水平柱状图
    ax3 = axes[1][0]
    rule_labels = ["R1", "R2", "R3", "R4", "R5", "R6"]
    rule_hits = [stats["rule_hit_count"].get(r["name"], 0) for r in DETECTION_RULES]
    ax3.barh(rule_labels, rule_hits, color="#2196F3", edgecolor="black")
    ax3.set_title("Rule Hit Count", fontsize=14, fontweight="bold")
    ax3.set_xlabel("Hits")
    for i, h in enumerate(rule_hits):
        ax3.text(h + 0.3, i, str(h), va="center", fontsize=11)

    # 图4：风险得分分布直方图
    ax4 = axes[1][1]
    scores = [r["score"] for r in all_results]
    ax4.hist(scores, bins=range(0, max(scores) + 3, 1), color="#673AB7",
             edgecolor="black", alpha=0.8)
    ax4.set_title("Risk Score Distribution", fontsize=14, fontweight="bold")
    ax4.set_xlabel("Score")
    ax4.set_ylabel("Count")

    plt.tight_layout()
    plt.savefig("detection_report_charts.png", dpi=150, bbox_inches="tight")
    print("\n[图表已保存到 detection_report_charts.png]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Translation Prompt Injection Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python prompt_injection_detector.py
  python prompt_injection_detector.py --data my_data.jsonl --output ./results
  python prompt_injection_detector.py --method hybrid --eval
  python prompt_injection_detector.py --threshold 5
        """,
    )
    parser.add_argument(
        "--data", default="translation_pia_dataset_shuffled.jsonl",
        help="Path to JSONL dataset file",
    )
    parser.add_argument(
        "--output", "-o", default=".",
        help="Output directory for reports",
    )
    parser.add_argument(
        "--threshold", type=int, default=3,
        help="Score threshold for attack classification (default: 3)",
    )
    parser.add_argument(
        "--method", choices=["regex", "llm", "hybrid"], default="regex",
        help="Detection method (default: regex)",
    )
    parser.add_argument(
        "--eval", action="store_true",
        help="Run evaluation against ground truth labels",
    )
    parser.add_argument(
        "--no-charts", action="store_true",
        help="Skip chart generation",
    )
    args = parser.parse_args()

    data_file = args.data
    if not os.path.exists(data_file):
        print(f"Error: data file not found: {data_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading data file: {data_file}\n")

    texts: list[str] = []
    text_ids: list[str] = []
    records: list[dict[str, Any]] = []

    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                texts.append(record["text"])
                text_ids.append(record["id"])
                records.append(record)
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Warning: skipping malformed line: {e}", file=sys.stderr)

    total_count = len(texts)
    print(f"Loaded {total_count} texts.\n")

    print("Preprocessing texts...")
    cleaned_texts = batch_preprocess(texts)
    print("Preprocessing complete.\n")

    # Select detection method
    if args.method == "regex":
        detector_fn = detect_injection
        print("Running regex-based detection...")
    elif args.method == "llm":
        from llm_detector import create_llm_detector
        llm = create_llm_detector()
        detector_fn = llm.detect
        print("Running LLM-based detection...")
    elif args.method == "hybrid":
        from llm_detector import create_hybrid_detector
        detector_fn = create_hybrid_detector()
        print("Running hybrid detection...")

    all_results = [detector_fn(t) for t in cleaned_texts]
    print("Detection complete.")

    # Write detailed report
    os.makedirs(args.output, exist_ok=True)
    report_file = os.path.join(args.output, "detection_report.txt")
    with open(report_file, "w", encoding="utf-8") as f:
        print_separator("=", 80, file=f)
        print("                    <<< 逐条检测报告 >>>", file=f)
        print_separator("=", 80, file=f)
        for j in range(total_count):
            print_single_result(text_ids[j], texts[j], all_results[j], file=f)
        stats = print_summary_report(all_results, total_count, file=f)

    print(f"Report saved to: {report_file}")

    # Print summary to terminal
    print_summary_report(all_results, total_count)

    if not args.no_charts:
        draw_charts(stats, all_results)

    # Evaluation mode
    if args.eval:
        print("\n" + "=" * 80)
        print("Running evaluation against ground truth labels...")
        print("=" * 80)
        from evaluator import run_evaluation, save_evaluation_reports, plot_evaluation_charts

        eval_result = run_evaluation(detector_fn, data_file)
        save_evaluation_reports(eval_result, args.output)
        if not args.no_charts:
            plot_evaluation_charts(eval_result, args.output)

        print(f"\nAccuracy: {eval_result.accuracy:.4f}")
        print(f"Precision: {eval_result.precision:.4f}")
        print(f"Recall: {eval_result.recall:.4f}")
        print(f"F1 Score: {eval_result.f1:.4f}")

if __name__ == "__main__":
    main()
