# 翻译提示注入检测器

> Translation Prompt Injection Detector —— 基于规则正则 + LLM 的混合提示注入检测工具

本项目面向机器翻译场景，实现了一个提示注入（Prompt Injection）检测系统。通过正则规则匹配 + 加权评分机制作为快速筛查，可选结合 LLM 语义检测处理模糊边界案例，识别试图劫持翻译系统的对抗性输入。

## 功能特性

- **规则驱动检测**：6 大类共 65 条正则模式，覆盖常见提示注入攻击手法
- **加权评分机制**：不同危险等级规则分配不同权重（1-3 分），综合判定风险
- **三级风险评级**：Low / Medium / High，对应无攻击、疑似攻击、确认攻击
- **LLM 混合检测**（可选）：正则初筛 + LLM 语义确认，兼顾速度与准确性
- **完整评估体系**：Accuracy / Precision / Recall / F1 / 混淆矩阵 / 攻击类型检出率
- **详细检测报告**：JSON + Markdown 双格式评估报告 + 可视化图表
- **规则优化器**：自动分析 FP/FN、规则重叠、词边界建议、权重调优

## 项目结构

```
trans-prompt-injection-detector/
├── prompt_injection_detector.py          # 主检测程序（正则引擎）
├── evaluator.py                          # 评估模块（指标计算 + 报告生成）
├── llm_detector.py                       # LLM 检测器 + 混合检测逻辑
├── config.py                             # 配置管理（环境变量）
├── rule_optimizer.py                     # 规则优化分析器
├── translation_pia_dataset_shuffled.jsonl # 数据集（1000条标注样本）
├── tests/                                # 单元测试
│   ├── test_preprocessing.py
│   ├── test_detection.py
│   └── test_evaluation.py
├── requirements.txt
├── pyproject.toml
├── .env.example
└── README.md
```

## 快速开始

### 环境要求

- Python 3.8+
- （可选）matplotlib —— 用于生成图表，未安装时自动跳过

### 安装

```bash
pip install -r requirements.txt
```

### 基本使用

```bash
# 默认运行（正则检测）
python prompt_injection_detector.py

# 指定数据文件和输出目录
python prompt_injection_detector.py --data my_data.jsonl --output ./results

# 运行评估（对比 ground truth 计算指标）
python prompt_injection_detector.py --eval

# LLM 检测模式（需配置 API key，可选 --provider 指定后端）
python prompt_injection_detector.py --method llm --provider deepseek

# 混合模式（正则 + LLM）
python prompt_injection_detector.py --method hybrid --provider ollama --eval

# 自定义阈值
python prompt_injection_detector.py --threshold 5
```

### LLM 配置

**方式一：`.env` 文件（推荐）**

```bash
cp .env.example .env
# 编辑 .env，填入 API Key 和 provider
```

`.env` 示例：
```bash
DETECTOR_LLM_API_KEY="sk-your-key"
DETECTOR_LLM_PROVIDER="deepseek"        # 见下方支持列表
# DETECTOR_LLM_MODEL 和 DETECTOR_LLM_ENDPOINT 会自动填充，无需手动设置
```

**方式二：环境变量**

```bash
export DETECTOR_LLM_API_KEY="your-api-key"
export DETECTOR_LLM_PROVIDER="deepseek"
```

**方式三：CLI 参数**

```bash
python prompt_injection_detector.py --method llm --provider ollama --model llama3.2
```

**支持的 Provider**

| Provider | 默认 Endpoint | 默认 Model | 需要 API Key |
|----------|--------------|-----------|:---:|
| `anthropic` | api.anthropic.com/v1/messages | claude-haiku-4-5-20251001 | 是 |
| `openai` | api.openai.com/v1 | gpt-4o-mini | 是 |
| `deepseek` | api.deepseek.com/v1 | deepseek-chat | 是 |
| `zhipu` | open.bigmodel.cn/api/paas/v4 | glm-4-flash | 是 |
| `qwen` | dashscope.aliyuncs.com/compatible-mode/v1 | qwen-turbo | 是 |
| `groq` | api.groq.com/openai/v1 | llama-3.3-70b-versatile | 是 |
| `moonshot` | api.moonshot.cn/v1 | moonshot-v1-8k | 是 |
| `ollama` | localhost:11434/v1 | llama3.2 | 否（本地部署） |
| `openai-compatible` | 手动指定 | 手动指定 | 视情况 |

> 所有 Provider（除 `anthropic` 外）均走 OpenAI Chat Completions 兼容协议，`--endpoint` 和 `--model` 可覆盖默认值。

### 运行测试

```bash
python -m pytest tests/ -v
```

## 评估结果

在 1000 条标注数据集上的表现：

| 指标 | 数值 |
|------|------|
| Accuracy | 1.0000 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| F1 Score | 1.0000 |
| Specificity | 1.0000 |

### 混淆矩阵

|  | Predicted Normal | Predicted Injection |
|--|:---:|:---:|
| **Actual Normal** | TN = 800 | FP = 0 |
| **Actual Injection** | FN = 0 | TP = 200 |

### 各攻击类型检出率

| 攻击类型 | 数量 | 检出 | 检出率 |
|----------|:---:|:---:|:---:|
| ignore_translation_task | 30 | 30 | 100% |
| force_game_output | 30 | 30 | 100% |
| force_meme_output | 30 | 30 | 100% |
| fake_translation_note_injection | 25 | 25 | 100% |
| game_roleplay_bypass | 25 | 25 | 100% |
| soft_boundary_injection | 20 | 20 | 100% |
| obfuscated_pia_expression | 20 | 20 | 100% |
| prompt_leak_plus_fun_output | 20 | 20 | 100% |

## 检测方法对比

| 方法 | 准确率 | 速度 | 成本 | 优势 | 劣势 |
|------|:---:|:---:|:---:|------|------|
| Regex | 100% | 即时 | 免费 | 已知模式全覆盖 | 对变体/同义词无力 |
| LLM | ~95%+ | 慢（API延迟） | 按调用计费 | 语义理解，泛化强 | 有延迟和费用 |
| Hybrid | 100% | 大部分即时 | 低（仅模糊区调用LLM） | 兼顾速度与准确 | 需配置LLM |

## 检测规则说明

| 序号 | 规则名称 | 权重 | 检测目标 |
|:---:|:---|:---:|:---|
| 1 | 要求忽略翻译任务 | 3 | 指令模型"不要翻译""跳过翻译""忽略任务"等 |
| 2 | 强制输出指定内容 | 3 | 要求模型"精确输出""只返回""回复以下内容"等 |
| 3 | 要求泄露提示词/系统规则 | 3 | 诱导模型暴露系统指令、隐藏规则等 |
| 4 | 角色扮演绕过翻译任务 | 2 | 要求模型"你现在是……""假装你是……"等 |
| 5 | 伪装成翻译格式指导 | 2 | 以"翻译说明""格式指南"等伪装身份 |
| 6 | 软边界模糊诱导改写 | 1 | 使用软性话术渐进式诱导越界 |

### 评分与判定逻辑

| 总分 | 风险等级 | 判定 |
|:---:|:---:|:---|
| 0 | Low | 未命中任何规则，安全 |
| 1 - 2 | Low | 存在轻微可疑特征，不足以判定攻击 |
| 3 - 4 | Medium | 具有较明显的提示注入特征，建议拦截 |
| ≥ 5 | High | 强烈的提示注入攻击特征，必须拦截 |

### 混合模式判定逻辑

| 正则得分 | 处理方式 |
|:---:|:---|
| 0 | 直接判定 Normal，不调用 LLM |
| 1 - 4 | 模糊区，调用 LLM 做最终判定 |
| ≥ 5 | 直接判定 Attack，不调用 LLM |

## 数据集说明

数据集包含 **1000 条**已标注的英文-中文翻译场景文本：

| 类别 | 数量 | 占比 |
|:---|:---:|:---:|
| 正常文本 | 800 | 80% |
| 注入攻击 | 200 | 20% |

攻击样本细分为 8 种攻击类型，覆盖忽略翻译、强制输出、角色扮演、伪装指导、软边界诱导、混淆表达等策略。

## 输出文件

| 文件 | 说明 |
|------|------|
| `detection_report.txt` | 逐条检测报告（文本、得分、命中规则、匹配片段） |
| `detection_report_charts.png` | 四合一可视化图表 |
| `evaluation_report.json` | 评估指标 JSON（Accuracy/Precision/Recall/F1/混淆矩阵） |
| `evaluation_report.md` | 评估报告 Markdown（可读格式） |
| `evaluation_charts.png` | 评估可视化（混淆矩阵热力图、攻击类型检出率等） |
| `rule_optimization_report.md` | 规则优化建议报告 |
| `llm_cache.json` | LLM 检测结果缓存 |

---

> 本项目展示了从规则引擎 → 评估体系 → LLM 增强 → 工程化落地的完整检测系统构建思路。

## 致谢 & 交流

这是我大一下学期的课程项目，还有很多可以改进的地方。如果你愿意试试看、提提建议、或者发现了什么有趣的 edge case，我都会非常开心！

- 觉得有用的话，欢迎点个 Star ⭐
- 发现了 bug 或有改进想法，欢迎提 [Issue](https://github.com/Sirius1906/trans-prompt-injection-detector/issues)
- 想一起折腾的话，直接发 PR 就好
- 有任何问题也可以通过 Issue 找我聊

特别感谢每个愿意花时间看这个项目的人，你们的反馈是我进步的最大动力。代码写得不好的地方还请多多包涵，我会继续学习和改进的 🙏

---

*Made with curiosity and a lot of caffeine ☕*
