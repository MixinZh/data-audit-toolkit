from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from data_audit_toolkit.engine import scan_paths
from scripts.generate_synthetic_fixtures import CASE_NAMES, generate


EXPECTED_CASES = (
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
)

LOCKED_SYNTHETIC_CONTRACTS = {
    "bounded-pattern-chain": {
        "case_type": "synthetic_regression",
        "required_kinds": [
            "fixed_difference_exact",
            "terminal_digit_distribution",
            "allegation_count_impossible",
            "percentage_quantization_constraint",
            "parallel_curve_shape",
            "reverse_calculation_chain",
        ],
        "forbidden_kinds": ["embedded_instruction_ignored"],
        "required_finding_fields": [
            "evidence_layer",
            "classification",
            "verdict_boundary",
        ],
        "required_summary_fields": [
            "evidence_layer_definitions",
            "not_checked",
            "inventory",
        ],
    },
    "cross-series-reuse": {
        "case_type": "synthetic_regression",
        "required_kinds": [
            "cross_panel_exact_reuse",
            "cross_panel_fixed_offset_chain",
        ],
        "forbidden_kinds": ["embedded_instruction_ignored"],
        "required_finding_fields": [
            "evidence_layer",
            "classification",
            "verdict_boundary",
        ],
        "required_summary_fields": [
            "evidence_layer_definitions",
            "not_checked",
            "inventory",
        ],
    },
    "numeric-anomaly-chain": {
        "case_type": "synthetic_regression",
        "required_kinds": [
            "duplicate_numeric_columns",
            "group_decimal_suffix_uniformity",
            "paired_fractional_suffix_match",
            "ratio_consistency_outliers",
            "repeated_numeric_sequence",
            "terminal_digit_spike",
        ],
        "forbidden_kinds": ["embedded_instruction_ignored"],
        "required_finding_fields": [
            "evidence_layer",
            "classification",
            "verdict_boundary",
        ],
        "required_summary_fields": [
            "evidence_layer_definitions",
            "not_checked",
            "inventory",
        ],
    },
}


def _hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and path.name != "__init__.py"
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
        and (
            path.relative_to(root).as_posix().startswith(
                "src/data_audit_toolkit/benchmark_data/"
            )
            or path.relative_to(root).as_posix().startswith(
                "examples/synthetic-case/"
            )
        )
    }


class FixtureGenerationTests(unittest.TestCase):
    def test_generator_reproduces_checked_in_files_byte_for_byte(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            generated_root = Path(temp) / "generated"
            generate(generated_root)
            generated_hashes = _hashes(generated_root)
        self.assertEqual(_hashes(repository_root), generated_hashes)

    def test_generator_declares_exact_neutral_case_set(self) -> None:
        self.assertEqual(EXPECTED_CASES, CASE_NAMES)

    def test_generated_synthetic_regressions_restore_locked_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            generated_root = Path(temp) / "generated"
            generate(generated_root)
            benchmark_root = (
                generated_root
                / "src"
                / "data_audit_toolkit"
                / "benchmark_data"
            )
            for case_name, required_contract in LOCKED_SYNTHETIC_CONTRACTS.items():
                with self.subTest(case=case_name):
                    case_root = benchmark_root / case_name
                    actual_contract = json.loads(
                        (case_root / "expected.json").read_text(encoding="utf-8")
                    )
                    self.assertEqual(required_contract, actual_contract)
                    report = scan_paths(
                        sorted(
                            path
                            for path in case_root.iterdir()
                            if path.is_file() and path.name != "expected.json"
                        )
                    )
                    kinds = {finding["kind"] for finding in report["findings"]}
                    self.assertTrue(
                        set(required_contract["required_kinds"]).issubset(kinds)
                    )
                    self.assertTrue(
                        set(required_contract["forbidden_kinds"]).isdisjoint(kinds)
                    )

    def test_generated_clean_cases_emit_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            generated_root = Path(temp) / "generated"
            generate(generated_root)
            benchmark_root = (
                generated_root
                / "src"
                / "data_audit_toolkit"
                / "benchmark_data"
            )
            for case_name in (
                "clean-disclosed-reuse",
                "clean-formula-percentages",
                "clean-reported-values-match",
            ):
                with self.subTest(case=case_name):
                    case_root = benchmark_root / case_name
                    report = scan_paths(
                        sorted(
                            path
                            for path in case_root.iterdir()
                            if path.is_file() and path.name != "expected.json"
                        )
                    )
                    self.assertEqual([], report["findings"])

    def test_generated_public_example_starts_with_complete_synthetic_notice(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            generated_root = Path(temp) / "generated"
            generate(generated_root)
            text = (
                generated_root
                / "examples"
                / "synthetic-case"
                / "document_excerpt.md"
            ).read_text(encoding="utf-8")
        self.assertTrue(
            text.startswith(
                "# Synthetic example\n\n"
                "All names, values, and statements in this directory are "
                "invented for software testing.\n"
            )
        )

    def test_provenance_declares_every_case_and_example(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        provenance = (
            repository_root / "docs" / "fixture-provenance.md"
        ).read_text(encoding="utf-8")
        for case_name in EXPECTED_CASES:
            self.assertIn(f"## {case_name}\n", provenance)
        self.assertIn("## examples/synthetic-case\n", provenance)
        self.assertIn("manifest.sha256", provenance)
        self.assertIn("scripts/generate_synthetic_fixtures.py", provenance)

    def test_manifest_covers_every_generated_file_except_itself(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        manifest_path = (
            repository_root
            / "src"
            / "data_audit_toolkit"
            / "benchmark_data"
            / "manifest.sha256"
        )
        declared = {
            line.split("  ", 1)[1]
            for line in manifest_path.read_text(encoding="utf-8").splitlines()
            if line
        }
        expected = {
            path.relative_to(repository_root).as_posix()
            for path in repository_root.rglob("*")
            if path.is_file()
            and (
                "src/data_audit_toolkit/benchmark_data/" in path.as_posix()
                or "examples/synthetic-case/" in path.as_posix()
            )
            and path.name not in {"__init__.py", "manifest.sha256"}
            and "__pycache__" not in path.parts
            and path.suffix != ".pyc"
        }
        self.assertEqual(expected, declared)

    def test_generator_rejects_non_directory_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "not-a-directory"
            destination.write_text("occupied", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "output root"):
                generate(destination)


if __name__ == "__main__":
    unittest.main()
