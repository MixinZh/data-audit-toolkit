from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


EXCLUDED_PARTS = {
    ".git",
    ".venv",
    ".worktrees",
    ".release-preview",
    ".superpowers",
    "__pycache__",
    "build",
    "dist",
}


def _public_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for candidate in root.rglob("*"):
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(root)
        if any(
            part in EXCLUDED_PARTS
            or part.endswith(".egg-info")
            or part.endswith(".pyc")
            for part in relative.parts
        ):
            continue
        files.append(candidate)
    return sorted(files)


class PublicHygieneTests(unittest.TestCase):
    def test_public_candidate_has_no_absolute_home_paths_or_secret_shapes(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        absolute_home_patterns = (
            re.compile(r"/Users/[A-Za-z0-9._-]+/"),
            re.compile(r"/home/[A-Za-z0-9._-]+/"),
        )
        secret_patterns = (
            re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
            re.compile(r"\bgh[opusr]_[A-Za-z0-9]{30,}\b"),
            re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
        )
        findings: list[str] = []
        for candidate in _public_files(root):
            content = candidate.read_bytes()
            text = content.decode("utf-8", errors="ignore")
            relative = candidate.relative_to(root).as_posix()
            for pattern in absolute_home_patterns:
                if pattern.search(text):
                    findings.append(f"{relative}: absolute home path")
            for pattern in secret_patterns:
                if pattern.search(text):
                    findings.append(f"{relative}: secret-shaped token")
        self.assertEqual([], findings)

    def test_generated_fixtures_use_only_neutral_synthetic_identifiers(self) -> None:
        root = Path(__file__).resolve().parents[1]
        generated_roots = (
            root / "src" / "data_audit_toolkit" / "benchmark_data",
            root / "examples" / "synthetic-case",
        )
        forbidden_patterns = (
            re.compile(r"\b10\.\d{4,9}/\S+", re.IGNORECASE),
            re.compile(r"\b(?:NCT|GSE|SRR|PMID|ORCID)\d+\b", re.IGNORECASE),
            re.compile(r"\b(?:University|Institute|Journal|Hospital)\b", re.IGNORECASE),
            re.compile(r"\b[A-Z][a-z]+,\s+[A-Z][a-z]+\b"),
        )
        findings: list[str] = []
        for generated_root in generated_roots:
            for candidate in sorted(generated_root.rglob("*")):
                if (
                    not candidate.is_file()
                    or candidate.suffix in {".png", ".pyc"}
                    or "__pycache__" in candidate.parts
                ):
                    continue
                text = candidate.read_text(encoding="utf-8")
                for pattern in forbidden_patterns:
                    if pattern.search(text):
                        findings.append(
                            f"{candidate.relative_to(root).as_posix()}: real identifier shape"
                        )
        self.assertEqual([], findings)

    def test_manifest_covers_all_generated_fixture_bytes(self) -> None:
        root = Path(__file__).resolve().parents[1]
        manifest = (
            root
            / "src"
            / "data_audit_toolkit"
            / "benchmark_data"
            / "manifest.sha256"
        )
        declared = {
            line.split("  ", 1)[1]
            for line in manifest.read_text(encoding="utf-8").splitlines()
            if line
        }
        generated = {
            path.relative_to(root).as_posix()
            for base in (
                root / "src" / "data_audit_toolkit" / "benchmark_data",
                root / "examples" / "synthetic-case",
            )
            for path in base.rglob("*")
            if path.is_file()
            and path.name not in {"__init__.py", "manifest.sha256"}
            and "__pycache__" not in path.parts
            and path.suffix != ".pyc"
        }
        self.assertEqual(generated, declared)

    def test_readme_uses_approved_neutral_positioning(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / "README.md").read_text(encoding="utf-8")
        folded = text.casefold()
        self.assertTrue(text.startswith("# Data Audit Toolkit\n"))
        self.assertIn(
            "An offline toolkit for finding reproducible consistency leads across local tables, text, and images.",
            text,
        )
        self.assertNotIn("research " + "audit", folded)
        self.assertNotIn("research " + "integrity", folded)
        self.assertIn("No account, upload, API key, or model is required.", text)

    def test_readme_preserves_the_approved_section_order(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / "README.md").read_text(encoding="utf-8")
        headings = [
            line
            for line in text.splitlines()
            if re.fullmatch(r"#{1,6} .+", line)
        ]
        self.assertEqual(
            [
                "# Data Audit Toolkit",
                "## What it does",
                "## Quick start",
                "### Use as a command-line tool",
                "### Use as an Agent Skill",
                "## Example result",
                "## Supported inputs",
                "## Privacy and boundaries",
                "## Testing",
                "## Contributing and security",
                "## License",
            ],
            headings,
        )

    def test_readme_not_checked_example_uses_runtime_file_key(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / "README.md").read_text(encoding="utf-8")
        json_block = text.split("```json\n", 1)[1].split("\n```", 1)[0]
        example = json.loads(json_block)
        self.assertIn("file", example["not_checked"][0])
        self.assertNotIn("path", example["not_checked"][0])


if __name__ == "__main__":
    unittest.main()
