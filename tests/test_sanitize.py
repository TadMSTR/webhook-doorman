"""Deterministic character removal: what goes, what stays, and what is counted.

Every assertion here names a class rather than a character count. The removed text is
producer-controlled and must never reach a log line or a metric label, so a test that asserted
on it would be encoding the thing the module exists to avoid.
"""

from __future__ import annotations

import sys
import unicodedata

import pytest

from webhook_doorman.sanitize import SANITIZE_CLASSES, sanitize, sanitize_structure


class TestRemovalClasses:
    @pytest.mark.parametrize(
        ("payload", "expected"),
        [
            # U+E0041 is a tag-block 'A' - invisible everywhere, text to a model.
            ("hello\U000e0041world", "tag"),
            ("hello\u202eworld", "bidi"),
            ("hello\u2066world", "bidi"),
            ("hello\u200bworld", "zero_width"),
            ("hello\ufeffworld", "zero_width"),
            ("hello\x00world", "control"),
            ("hello\x1bworld", "control"),
            ("hello\x7fworld", "control"),
            ("hello\x9bworld", "control"),
        ],
    )
    def test_each_class_is_stripped_and_named(self, payload, expected):
        cleaned, classes = sanitize(payload)
        assert cleaned == "helloworld"
        assert expected in classes

    def test_the_three_kept_controls_survive(self):
        """Tab, newline and carriage return legitimately appear in a webhook body."""
        cleaned, classes = sanitize("a\tb\nc\rd")
        assert cleaned == "a\tb\nc\rd"
        assert classes == frozenset()

    def test_ordinary_text_is_untouched(self):
        cleaned, classes = sanitize("Fix A & B — done ✅")
        assert cleaned == "Fix A & B — done ✅"
        assert classes == frozenset()

    def test_nfkc_folds_a_compatibility_form(self):
        cleaned, classes = sanitize("\uff1cscript\uff1e")
        assert cleaned == "<script>"
        assert "normalized" in classes

    def test_several_classes_are_reported_together(self):
        cleaned, classes = sanitize("a\u200bb\u202ec\x00d")
        assert cleaned == "abcd"
        assert classes == frozenset({"zero_width", "bidi", "control"})

    def test_every_reported_class_is_in_the_closed_vocabulary(self):
        _, classes = sanitize("a\u200b\u202e\x00\U000e0041\uff1c")
        assert classes <= set(SANITIZE_CLASSES)

    def test_it_is_idempotent(self):
        """Sanitising a sanitised string changes nothing and reports nothing."""
        once, _ = sanitize("a\u200bb\uff1cc\x00d")
        twice, classes = sanitize(once)
        assert twice == once
        assert classes == frozenset()


class TestOrdering:
    def test_nfkc_never_produces_a_stripped_character(self):
        """The reason NFKC runs first, checked rather than assumed.

        If any clean codepoint normalised into a character this module strips, then normalising
        after stripping would reintroduce it and the guarantee would hold only for the input.
        Sweeping the whole codespace is the only way to state that as a fact; a future Unicode
        release that changed it would fail here rather than silently in production.
        """
        offenders = []
        for point in range(sys.maxunicode + 1):
            char = chr(point)
            _, classes = sanitize(char)
            if classes - {"normalized"}:
                continue  # Already stripped; not a source of new characters.
            folded = unicodedata.normalize("NFKC", char)
            _, folded_classes = sanitize(folded)
            if folded_classes - {"normalized"}:
                offenders.append(hex(point))
        assert offenders == []


class TestStructure:
    def test_it_walks_nested_values_and_preserves_shape(self):
        classes: set[str] = set()
        out = sanitize_structure(
            {"a": "x\u200by", "b": [{"c": "p\x00q"}], "d": 5, "e": None, "f": True},
            classes,
        )
        assert out == {"a": "xy", "b": [{"c": "pq"}], "d": 5, "e": None, "f": True}
        assert classes == {"zero_width", "control"}

    def test_a_clean_structure_reports_nothing(self):
        classes: set[str] = set()
        value = {"a": "clean", "b": [1, 2, 3]}
        assert sanitize_structure(value, classes) == value
        assert classes == set()
