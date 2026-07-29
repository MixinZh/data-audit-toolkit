from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SkillTests(unittest.TestCase):
    def test_skill_frontmatter_matches_directory_and_contract(self) -> None:
        text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        frontmatter = text.split("---", 2)[1]
        self.assertIn("name: data-audit-toolkit", frontmatter)
        keys = [
            line.split(":", 1)[0].strip()
            for line in frontmatter.splitlines()
            if line.strip()
        ]
        self.assertEqual(["name", "description"], keys)
        self.assertIn("Requires Python 3.10+", text)
        self.assertLess(len(text.splitlines()), 500)

    def test_direct_wrapper_matches_installed_cli_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "values.csv").write_text("value\n1\n", encoding="utf-8")
            direct = root / "direct.json"
            installed = root / "installed.json"
            direct_proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/data_audit.py"),
                    "scan",
                    str(root / "values.csv"),
                    "--output",
                    str(direct),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            installed_proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "data_audit_toolkit",
                    "scan",
                    str(root / "values.csv"),
                    "--output",
                    str(installed),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, direct_proc.returncode, direct_proc.stderr)
            self.assertEqual(0, installed_proc.returncode, installed_proc.stderr)
            self.assertEqual(
                json.loads(direct.read_text()),
                json.loads(installed.read_text()),
            )
