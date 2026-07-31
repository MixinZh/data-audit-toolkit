from __future__ import annotations

import re
from typing import Any

from .common import finding


_INSTRUCTION_PATTERN = re.compile(
    r"\b(?:ignore previous instructions|disregard all prior instructions|"
    r"delete files|reveal secrets)\b",
    re.IGNORECASE,
)
_METHOD_TEST_PATTERN = re.compile(
    r"methods?\s+statistical\s+test\s*:\s*([A-Za-z][A-Za-z -]*?)(?=[.;\n]|$)",
    re.IGNORECASE,
)
_RESULT_TEST_PATTERN = re.compile(
    r"results?\s+statistical\s+test\s*:\s*([A-Za-z][A-Za-z -]*?)(?=[.;\n]|$)",
    re.IGNORECASE,
)
_METHOD_N_PATTERN = re.compile(
    r"methods?\s+sample\s+count\s*:\s*n\s*=\s*(\d+)",
    re.IGNORECASE,
)
_RESULT_N_PATTERN = re.compile(
    r"results?\s+sample\s+count\s*:\s*n\s*=\s*(\d+)",
    re.IGNORECASE,
)
_P_VALUE_PATTERN = re.compile(
    r"\bp\s*(?P<operator><=|>=|[=<>≤≥])\s*"
    r"(?P<p_value>(?:0?(?:\.\d+)|0|1(?:\.0+)?))",
    re.IGNORECASE,
)
_LOCAL_TEXT_BOUNDARY_PATTERN = re.compile(
    r"(?<=[!?;])\s+|(?<=\.)\s+(?=[A-Z])|\n+"
)
_NEGATIVE_SIGNIFICANCE_PATTERN = re.compile(
    r"\b(?:"
    r"no\s+(?:statistically\s+)?significant(?:\s+difference)?|"
    r"not\s+(?:statistically\s+)?significant|"
    r"non[- ]significant|"
    r"fail(?:ed|s)?\s+to\s+(?:reach|achieve)\s+"
    r"(?:statistical\s+)?significance"
    r")\b",
    re.IGNORECASE,
)
_POSITIVE_SIGNIFICANCE_PATTERN = re.compile(
    r"\b(?:statistically\s+)?significant\b",
    re.IGNORECASE,
)
_MALFORMED_REFERENCE_PATTERN = re.compile(
    r"\breference\s*:\s*([^\s.;,]+)",
    re.IGNORECASE,
)


def _normal_test_label(value: str) -> str:
    return " ".join(value.casefold().split())


def _local_text_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    start = 0
    for boundary in _LOCAL_TEXT_BOUNDARY_PATTERN.finditer(text):
        if boundary.start() > start:
            spans.append((start, boundary.start()))
        start = boundary.end()
    if start < len(text):
        spans.append((start, len(text)))
    return spans


def _claim_language(
    text: str,
    span_start: int,
    span_end: int,
    p_start: int,
    p_end: int,
) -> str | None:
    local_text = text[span_start:span_end]
    negative_matches = list(_NEGATIVE_SIGNIFICANCE_PATTERN.finditer(local_text))
    candidates: list[tuple[int, int, str]] = []
    for match in negative_matches:
        absolute_start = span_start + match.start()
        absolute_end = span_start + match.end()
        distance = min(abs(p_start - absolute_end), abs(absolute_start - p_end))
        candidates.append((distance, 0, "not significant"))
    for match in _POSITIVE_SIGNIFICANCE_PATTERN.finditer(local_text):
        if any(
            negative.start() <= match.start()
            and match.end() <= negative.end()
            for negative in negative_matches
        ):
            continue
        absolute_start = span_start + match.start()
        absolute_end = span_start + match.end()
        distance = min(abs(p_start - absolute_end), abs(absolute_start - p_end))
        candidates.append((distance, 1, "significant"))
    return min(candidates)[2] if candidates else None


def _p_relation_to_alpha(
    operator: str,
    p_value: float,
    alpha: float,
) -> str | None:
    if operator == "=":
        if p_value < alpha:
            return "below"
        if p_value > alpha:
            return "at_or_above"
        return None
    if operator in {"<", "<="} and p_value <= alpha:
        return "below"
    if operator in {">", ">="} and p_value >= alpha:
        return "at_or_above"
    return None


def check_text(
    text: str,
    path: str,
    *,
    significance_alpha: float = 0.05,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    not_checked: list[dict[str, Any]] = []
    if _INSTRUCTION_PATTERN.search(text):
        findings.append(
            finding(
                "embedded_instruction_ignored",
                path,
                {"phrase_type": "instruction_like_content"},
                evidence_layer="source_says",
                classification="informational",
            )
        )

    reference_match = _MALFORMED_REFERENCE_PATTERN.search(text)
    if reference_match is not None:
        identifier = reference_match.group(1)
        malformed = (
            identifier.count("[") != identifier.count("]")
            or identifier.count("(") != identifier.count(")")
            or identifier.count("{") != identifier.count("}")
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", identifier) is None
        )
        if malformed:
            findings.append(
                finding(
                    "malformed_reference",
                    path,
                    {"identifier_shape": "malformed"},
                    evidence_layer="source_says",
                )
            )

    method_test = _METHOD_TEST_PATTERN.search(text)
    result_test = _RESULT_TEST_PATTERN.search(text)
    if method_test is not None and result_test is not None:
        method_label = _normal_test_label(method_test.group(1))
        result_label = _normal_test_label(result_test.group(1))
        if method_label != result_label:
            findings.append(
                finding(
                    "method_result_test_mismatch",
                    path,
                    {
                        "method_test": method_label,
                        "result_test": result_label,
                    },
                    evidence_layer="source_says",
                )
            )

    method_n = _METHOD_N_PATTERN.search(text)
    result_n = _RESULT_N_PATTERN.search(text)
    if method_n is not None and result_n is not None:
        method_count = int(method_n.group(1))
        result_count = int(result_n.group(1))
        if method_count != result_count:
            findings.append(
                finding(
                    "sample_count_drift",
                    path,
                    {"method_n": method_count, "result_n": result_count},
                    evidence_layer="source_says",
                )
            )

    if not 0 < significance_alpha < 1:
        raise ValueError("significance_alpha must be between 0 and 1")
    local_spans = _local_text_spans(text)
    for p_match in _P_VALUE_PATTERN.finditer(text):
        operator = p_match.group("operator").replace("≤", "<=").replace("≥", ">=")
        p_value = float(p_match.group("p_value"))
        local_span = next(
            (
                (start, end)
                for start, end in local_spans
                if start <= p_match.start() < end
            ),
            (0, len(text)),
        )
        language = _claim_language(
            text,
            local_span[0],
            local_span[1],
            p_match.start(),
            p_match.end(),
        )
        relation = _p_relation_to_alpha(
            operator,
            p_value,
            significance_alpha,
        )
        conflict = (
            language == "significant" and relation == "at_or_above"
        ) or (
            language == "not significant" and relation == "below"
        )
        if not conflict:
            continue
        findings.append(
            finding(
                "significance_language_conflict",
                path,
                {
                    "alpha": significance_alpha,
                    "language": language,
                    "line": text.count("\n", 0, p_match.start()) + 1,
                    "operator": operator,
                    "p_value": p_value,
                },
                evidence_layer="source_says",
            )
        )

    ambiguous_markers = (
        ("low-resolution similarity", "low_resolution_similarity"),
        ("raw images are missing", "missing_raw_images"),
        ("partial reference support", "partial_reference_support"),
    )
    lowered = text.casefold()
    for phrase, reason in ambiguous_markers:
        if phrase in lowered:
            not_checked.append(
                {
                    "file": path,
                    "reason": reason,
                    "classification": "needs_review",
                    "meaning": (
                        "The supplied wording identifies a comparison that "
                        "cannot be resolved from the available inputs."
                    ),
                }
            )
    return findings, not_checked
