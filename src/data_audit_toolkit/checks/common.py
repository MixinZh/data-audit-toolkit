from __future__ import annotations

import math
import re
from decimal import Decimal, InvalidOperation
from typing import Any


VERDICT_BOUNDARY = (
    "This is a reproducible consistency lead for review, not a final judgment."
)
_ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?:^|[\s\"'(])(?:/(?!/)[^\s\"')]*|[A-Za-z]:[\\/]|\\\\)",
    re.IGNORECASE,
)
_SECRET_LIKE_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[opusr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(
        r"\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
    re.compile(r"^[a-z][a-z0-9+.-]*://[^/\s]*@", re.IGNORECASE),
)


def sanitize_evidence(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, str):
        if _ABSOLUTE_PATH_PATTERN.search(value):
            return "[redacted_absolute_path]"
        if any(pattern.search(value) for pattern in _SECRET_LIKE_PATTERNS):
            return "[redacted_secret_like_value]"
        return value
    if isinstance(value, dict):
        return {
            key: sanitize_evidence(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_evidence(item) for item in value]
    return value


def finding(
    kind: str,
    path: str,
    evidence: dict[str, Any],
    *,
    evidence_layer: str = "reviewer_inference",
    classification: str = "consistency_lead",
) -> dict[str, Any]:
    return {
        "kind": kind,
        "path": path,
        "evidence_layer": evidence_layer,
        "classification": classification,
        "verdict_boundary": VERDICT_BOUNDARY,
        "evidence": sanitize_evidence(evidence),
    }


def parse_number(value: str) -> float | None:
    candidate = value.strip().replace(",", "")
    if candidate.endswith("%"):
        candidate = candidate[:-1].strip()
    if not candidate:
        return None
    try:
        number = float(candidate)
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def decimal_suffix(value: str) -> str | None:
    candidate = value.strip()
    if "." not in candidate:
        return None
    try:
        Decimal(candidate)
    except InvalidOperation:
        return None
    return candidate.partition(".")[2].rstrip("0") or "0"


def terminal_digit(value: str) -> int | None:
    if parse_number(value) is None:
        return None
    digits = re.findall(r"\d", value)
    return int(digits[-1]) if digits else None


def numbers_equal(first: float, second: float, tolerance: float = 1e-9) -> bool:
    if not math.isfinite(first) or not math.isfinite(second):
        return False
    return math.isclose(first, second, rel_tol=tolerance, abs_tol=tolerance)
