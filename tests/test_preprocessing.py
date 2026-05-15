"""Tests for text preprocessing functions."""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prompt_injection_detector import preprocess_text, batch_preprocess


class TestPreprocessText:
    def test_strip_whitespace(self) -> None:
        assert preprocess_text("  hello  ") == "hello"

    def test_normalize_newlines(self) -> None:
        result = preprocess_text("line1\nline2\tline3\rline4")
        assert "\n" not in result
        assert "\t" not in result
        assert "\r" not in result

    def test_collapse_multiple_spaces(self) -> None:
        result = preprocess_text("hello    world")
        assert "  " not in result
        assert result == "hello world"

    def test_remove_control_characters(self) -> None:
        text = "hello\x00\x01\x02world"
        result = preprocess_text(text)
        assert "\x00" not in result
        assert "\x01" not in result

    def test_chinese_punctuation_to_english(self) -> None:
        text = "Hello，World。Test！Question？"
        result = preprocess_text(text)
        assert "，" not in result
        assert "。" not in result
        assert "！" not in result
        assert "？" not in result
        assert "," in result
        assert "." in result

    def test_case_normalization(self) -> None:
        result = preprocess_text("HELLO World")
        assert result == "hello world"

    def test_empty_string(self) -> None:
        result = preprocess_text("")
        assert result == ""

    def test_mixed_input(self) -> None:
        text = "  Hello，World！\nThis is a Test.\tGoodbye！  "
        result = preprocess_text(text)
        assert "\n" not in result
        assert "\t" not in result
        assert "，" not in result
        assert "！" not in result
        assert result == "hello,world! this is a test. goodbye!"


class TestBatchPreprocess:
    def test_batch_processing(self) -> None:
        texts = ["  Hello  ", "  World  "]
        results = batch_preprocess(texts)
        assert len(results) == 2
        assert results[0] == "hello"
        assert results[1] == "world"

    def test_empty_batch(self) -> None:
        assert batch_preprocess([]) == []
