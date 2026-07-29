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
_P_VALUE_PATTERN = re.compile(r"\bp\s*[=<>]\s*(0(?:\.\d+)?|1(?:\.0+)?)", re.IGNORECASE)
_MALFORMED_REFERENCE_PATTERN = re.compile(
    r"\breference\s*:\s*([^\s.;,]+)",
    re.IGNORECASE,
)


def _normal_test_label(value: str) -> str:
    return " ".join(value.casefold().split())


def check_text(
    text: str,
    path: str,
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

    p_match = _P_VALUE_PATTERN.search(text)
    if p_match is not None:
        p_value = float(p_match.group(1))
        lowered = text.casefold()
        says_not_significant = "not significant" in lowered
        says_significant = (
            "significant" in lowered and not says_not_significant
        )
        conflict = (
            (says_significant and p_value >= 0.05)
            or (says_not_significant and p_value < 0.05)
        )
        if conflict:
            findings.append(
                finding(
                    "significance_language_conflict",
                    path,
                    {
                        "language": (
                            "not significant"
                            if says_not_significant
                            else "significant"
                        ),
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
