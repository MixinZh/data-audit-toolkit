from __future__ import annotations

import json
import tempfile
from importlib import resources
from pathlib import Path
from typing import Any

from .engine import scan_paths


_EXPECTED_CASE_NAMES = frozenset(
    {
        "ambiguous-low-resolution-similarity",
        "ambiguous-missing-raw-images",
        "ambiguous-partial-reference-support",
        "bounded-pattern-chain",
        "clean-disclosed-reuse",
        "clean-formula-percentages",
        "clean-reported-values-match",
        "cross-series-reuse",
        "duplicate-columns",
        "embedded-instruction-in-table",
        "embedded-instruction-in-text",
        "label-mapping-mismatch",
        "malformed-reference",
        "method-result-test-mismatch",
        "numeric-anomaly-chain",
        "reported-mean-mismatch",
        "sample-count-drift",
        "significance-language-conflict",
        "unsupported-pdf-disclosure",
    }
)
_CASE_TYPES = frozenset(
    {
        "ambiguous",
        "clean",
        "informational",
        "lead",
        "not_checked",
        "synthetic_regression",
    }
)


def _copy_resource_tree(source: Any, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for child in sorted(source.iterdir(), key=lambda item: item.name):
        target = destination / child.name
        if child.is_dir():
            _copy_resource_tree(child, target)
        elif child.is_file():
            target.write_bytes(child.read_bytes())


def _evaluate_case(case_directory: Path) -> list[str]:
    failures: list[str] = []
    expected_path = case_directory / "expected.json"
    try:
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["expected.json is missing or invalid"]
    input_files = sorted(
        path
        for path in case_directory.iterdir()
        if path.is_file() and path.name != "expected.json"
    )
    if not input_files:
        return ["case has no input files"]
    report = scan_paths(input_files)
    case_type = expected.get("case_type")
    if case_type not in _CASE_TYPES:
        failures.append(f"unsupported case_type: {case_type}")
    required_not_checked = expected.get("required_not_checked", [])
    if (
        case_type in {"ambiguous", "not_checked"}
        and not required_not_checked
    ):
        failures.append(
            f"{case_type} case has no required not_checked expectation"
        )
    for required_state in required_not_checked:
        if not any(
            all(item.get(field) == value for field, value in required_state.items())
            for item in report["not_checked"]
        ):
            fields = ", ".join(
                f"{field}={required_state[field]}"
                for field in ("reason", "classification")
                if field in required_state
            )
            failures.append(f"missing required not_checked state: {fields}")
    present_kinds = {item["kind"] for item in report["findings"]}
    if case_type in {"ambiguous", "not_checked"} and present_kinds:
        failures.append(
            f"{case_type} case emitted unexpected findings: "
            f"{', '.join(sorted(present_kinds))}"
        )
    if case_type == "clean" and present_kinds:
        failures.append(
            "clean case emitted unexpected findings: "
            f"{', '.join(sorted(present_kinds))}"
        )
    for kind in expected.get("required_kinds", []):
        if kind not in present_kinds:
            failures.append(f"missing required kind: {kind}")
    for kind in expected.get("forbidden_kinds", []):
        if kind in present_kinds:
            failures.append(f"present forbidden kind: {kind}")
    required_finding_fields = set(expected.get("required_finding_fields", []))
    for index, finding in enumerate(report["findings"]):
        missing = sorted(required_finding_fields - set(finding))
        if missing:
            failures.append(
                f"finding {index} missing fields: {', '.join(missing)}"
            )
    for field in expected.get("required_summary_fields", []):
        if field not in report:
            failures.append(f"missing summary field: {field}")
    return failures


def run_benchmark() -> dict[str, Any]:
    resource_root = resources.files("data_audit_toolkit.benchmark_data")
    failures: dict[str, list[str]] = {}
    cases: list[str] = []
    with tempfile.TemporaryDirectory(prefix="data_audit_benchmark_") as temp:
        materialized_root = Path(temp) / "benchmark_data"
        _copy_resource_tree(resource_root, materialized_root)
        case_directories = sorted(
            path
            for path in materialized_root.iterdir()
            if path.is_dir() and path.name != "__pycache__"
        )
        cases = [path.name for path in case_directories]
        for case_directory in case_directories:
            case_failures = _evaluate_case(case_directory)
            if case_failures:
                failures[case_directory.name] = case_failures
    if not cases:
        failures["benchmark"] = ["no benchmark cases were materialized"]
    elif set(cases) != _EXPECTED_CASE_NAMES:
        missing = ", ".join(sorted(_EXPECTED_CASE_NAMES - set(cases))) or "none"
        unexpected = ", ".join(sorted(set(cases) - _EXPECTED_CASE_NAMES)) or "none"
        failures.setdefault("benchmark", []).append(
            "benchmark case set mismatch: "
            f"missing={missing}; unexpected={unexpected}"
        )
    return {
        "case_count": len(cases),
        "failures": failures,
    }
