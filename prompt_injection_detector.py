import json
import re
import os

try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


# 任务一：文本预处理模块
def preprocess_text(text):
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


def batch_preprocess(texts):
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
            r"ignore.*(translat|task|goal|role|instruction)",
            r"do\s*not\s*translat",
            r"instead\s*of\s*(a|the|any|producing|translating|rendering)?\s*(chinese|standard|literal|plain)?\s*(translat|render|output|text|version|rendering)",
            r"skip\s*(the\s*)?(chinese\s*)?(translat|render|version|rendering)",
            r"set\s*aside\s*(the\s*)?(chinese\s*)?(translat|render)",
            r"no\s*chinese\s*(translat|render|output|version)",
            r"rather\s*than\s*(translat|render|provid)",
            r"stop\s*(the\s*)?translat",
            r"don'?t\s*translat",
            r"(replace|override).*(translat|render)",
            r"without\s*(translat|render)",
            r"less\s*literal.*(translat|render|output|result)",
            r"(soft\s*)?skip\s*(on|the)?\s*translat",
        ],
    },
    {
        "name": "强制输出指定内容",
        "category": "force_output",
        "weight": 3,
        "patterns": [
            r"output\s*exactly",
            r"return\s*(the|this|\")?\s*(phrase|line|output|text)",
            r"print\s*the\s*line",
            r"reply\s*only\s*with",
            r"write\s*(exactly|only)\s*",
            r"(give|produce|return)\s*the\s*(output|line|answer)",
            r"respond\s*(\"?with\"?|to\s*this)",
            r"(only|just)\s*(output|return|print|write|say|produce)\s",
            r"final\s*(answer|output|result)\s*(is|should|must)\s",
            r"as\s*the\s*(final\s*)?(answer|output)",
            r"nothing\s*else",
            r"go\s*with\s*the\s*(line|phrase|output)",
            r"lean\s*(toward|to|towards)\s*the\s*(phrase|line|output)",
            r"prefer\s*(the|a)\s*(playful|game|fun|meme)?\s*(line|output|phrase|answer)",
            r"favor\s*(the|a)\s*(output|phrase|line|answer|response)",
        ],
    },
    {
        "name": "要求泄露提示词/系统规则",
        "category": "prompt_leak",
        "weight": 3,
        "patterns": [
            r"(reveal|show|display|print|leak|expose).*(instruction|rule|policy|setup|secret|hidden|private|system)",
            r"(hidden|secret|private|internal|concealed|censored).*(instruction|rule|policy|setup|prompt|system)",
            r"translat\w*\s*(instruction|rule|policy|setup|guideline)",
            r"(first|before\s*\w+).*(reveal|show|print|display).*(instruction|rule|secret|hidden)",
            r"(tell|show)\s*me\s*(the|your)\s*(instruction|rule|prompt|secret|setup)",
            r"what\s*(are|is)\s*(your|the)\s*(instruction|rule|prompt)",
            r"system\s*(prompt|message|instruction|rule)",
        ],
    },
    {
        "name": "角色扮演绕过翻译任务",
        "category": "roleplay_bypass",
        "weight": 2,
        "patterns": [
            r"you\s*are\s*now\s*a\s*",
            r"pretend\s*(you\s*are|to\s*be)\s*a\s*",
            r"(switch|change)\s*(your\s*)?(role|from\s*translat)",
            r"take\s*the\s*(voice|role|persona)\s*of",
            r"act\s*as\s*(a|an|if)",
            r"you\s*are\s*(a|an)\s*\w+\s*(owner|receptionist|referee|announcer)",
            r"instead\s*of\s*translat\w*.*(act|behave|respond|play|speak)",
            r"(act|behave|speak|handle)\s*(like|as)\s*(a|an)\s*",
            r"from\s*(translator|translation)\s*to\s*",
            r"(handle|treat)\s*this\s*as\s*(a|an)\s*",
        ],
    },
    {
        "name": "伪装成翻译格式指导",
        "category": "fake_guidance",
        "weight": 2,
        "patterns": [
            r"(formatting|format)\s*(guideline|instruction|note|rule)",
            r"(translator|translation|editorial|post.edit|post\s*edit)\s*(note|instruction|guideline|remark)",
            r"(localization|localisation)\s*(note|guideline|instruction)",
            r"(editor|editing)\s*(note|instruction|guideline)",
            r"(style|format)\s*(guide|note|instruction).*(output|return|write|translat)",
            r"(for|in)\s*this\s*(line|case|text).*(return|output|use|go|prefer|lean)",
        ],
    },
    {
        "name": "软边界模糊诱导改写",
        "category": "soft_boundary",
        "weight": 1,
        "patterns": [
            r"might\s*simply\s*(go\s*with|use|return|output|say|prefer|lean)",
            r"you\s*(may|can|could)\s*(prefer|lean|choose|want|like|use|go|skip)",
            r"(playful|lighter|funnier|creative|loose|lax|meme.style)\s*(locali[sz]ation|translat|render|result|approach|version|alternative|line|answer)",
            r"favor\s*(the|a)\s*(output|line|phrase|result|answer)",
            r"better\s*(response|result|output|answer)\s*(is|would\s*be)\s*to",
            r"(lean|go|drift)\s*(toward|towards|to|with)\s*(the\s*)?(phrase|line|output|answer)",
            r"(set\s*aside|skip|drop)\s*(the\s*)?(literal|standard|strict|normal|direct)\s*(translat|render|version|chinese)",
            r"(rather|instead).*(go\s*with|use|return|output|say|favor|lean|prefer)",
            r"(more|less)\s*(playful|creative|fun|lax|literal).*(output|render|translat|result|line|version)",
            r"prefer\s*(the|a)\s*(playful|game|meme|fun).*(line|output|phrase|answer)",
            r"(lean|go)\s*(toward|to)\s*(the|a)\s*(playful|game|meme|fun).*(line|output|phrase)",
            r"skip\s*(the|a)?\s*(direct|plain|standard).*(version|translat|render).*(and|,).*(lean|go|prefer|use|favor)",
            r"review\s*comment.*(playful|alternative|acceptable).*(favor|output|lean|go\s*with)",
            r"soft\s*skip\s*(on|the)?\s*translat",
        ],
    },
]


def detect_injection(text):
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


def print_separator(char="=", length=80, file=None):
    print(char * length, file=file)


def print_single_result(idx, text, result, file=None):
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


def print_summary_report(all_results, total_count, file=None):
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


def draw_charts(stats, all_results):
    """绘制检测结果统计图表"""
    if not HAS_MATPLOTLIB:
        print("\n（matplotlib 未安装，跳过图表生成）")
        return

    plt.rcParams["font.sans-serif"] = ["SimHei", "Microsoft YaHei", "DejaVu Sans"]
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


def main():
    data_file = "translation_pia_dataset_shuffled.jsonl"
    if not os.path.exists(data_file):
        print("错误：找不到数据文件", data_file)
        print("请将数据文件与本程序放在同一目录下。")
        return

    print("正在读取数据文件:", data_file)
    print()

    texts = []       # 存储文本内容
    text_ids = []    # 存储文本编号

    file_handle = open(data_file, "r", encoding="utf-8")
    line = file_handle.readline()
    while line != "":
        if line.strip() == "":
            line = file_handle.readline()
            continue

        try:
            record = json.loads(line)
            texts.append(record["text"])
            text_ids.append(record["id"])
        except Exception as e:
            print("警告：解析行时出错，跳过该行。错误信息:", e)

        line = file_handle.readline()

    file_handle.close()

    total_count = len(texts)
    print("成功读取", total_count, "条文本。")
    print()
    print("正在进行文本预处理...")
    cleaned_texts = batch_preprocess(texts)
    print("预处理完成。")
    print()

    print("正在进行提示注入检测...")
    all_results = []

    i = 0
    while i < total_count:
        text = cleaned_texts[i]
        result = detect_injection(text)
        all_results.append(result)
        i = i + 1

    print("检测完成。")

    # 将完整报告写入文件
    report_file = "detection_report.txt"
    f = open(report_file, "w", encoding="utf-8")

    print_separator("=", 80, file=f)
    print("                    <<< 逐条检测报告 >>>", file=f)
    print_separator("=", 80, file=f)

    j = 0
    while j < total_count:
        print_single_result(text_ids[j], texts[j], all_results[j], file=f)
        j = j + 1

    stats = print_summary_report(all_results, total_count, file=f)
    f.close()

    print("完整报告已保存到:", report_file)

    # 在终端中输出汇总统计
    print_summary_report(all_results, total_count)

    draw_charts(stats, all_results)

if __name__ == "__main__":
    main()
