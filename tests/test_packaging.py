from __future__ import annotations

import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts import release_check


ROOT = Path(__file__).resolve().parents[1]
APACHE_2_0_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"


class PackagingMetadataTests(unittest.TestCase):
    def test_required_public_files_exist(self) -> None:
        for name in (
            "README.md",
            "LICENSE",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "CHANGELOG.md",
            "SKILL.md",
        ):
            self.assertTrue((ROOT / name).is_file(), name)

    def test_pyproject_names_readme_and_license(self) -> None:
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('readme = "README.md"', text)
        self.assertIn('license = "Apache-2.0"', text)
        self.assertIn('license-files = ["LICENSE"]', text)
        self.assertIn(
            '"Documentation" = "https://github.com/MixinZh/data-audit-toolkit#readme"',
            text,
        )

    def test_license_is_the_unmodified_apache_2_0_text(self) -> None:
        digest = hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
        self.assertEqual(APACHE_2_0_SHA256, digest)

    def test_benchmark_resources_are_declared_as_package_data(self) -> None:
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('data_audit_toolkit = ["benchmark_data/**/*"]', text)

    def test_release_check_accepts_generic_forbidden_terms(self) -> None:
        parser = release_check.build_parser()
        args = parser.parse_args(
            ["--forbid-term", "first-marker", "--forbid-term", "second-marker"]
        )
        self.assertEqual(["first-marker", "second-marker"], args.forbid_term)

    def test_release_scanner_checks_relative_filenames_and_file_contents(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            named = root / "nested-first-marker" / "clean.txt"
            named.parent.mkdir()
            named.write_text("neutral\n", encoding="utf-8")
            (root / "content.txt").write_text(
                "contains SECOND-MARKER\n",
                encoding="utf-8",
            )

            findings = release_check.scan_candidate_tree(
                root,
                ["first-marker", "second-marker"],
            )

        self.assertEqual(
            {
                ("content.txt", "forbidden_term"),
                ("nested-first-marker/clean.txt", "forbidden_term"),
            },
            {(item["path"], item["kind"]) for item in findings},
        )

    def test_release_scanner_detects_private_paths_tokens_and_keys(self) -> None:
        separator = chr(92)
        cases = {
            "users.txt": "/" + "Users" + "/example/private.txt",
            "home.txt": "/" + "home" + "/example/private.txt",
            "drive.txt": "C:" + separator + "Users" + separator + "example",
            "unc.txt": separator * 2 + "server" + separator + "share",
            "tilde.txt": "~" + "/private/file.txt",
            "openai.txt": "sk-" + ("a" * 24),
            "github.txt": "gh" + "p_" + ("b" * 32),
            "aws.txt": "AK" + "IA" + ("C" * 16),
            "private-key.txt": (
                ("-" * 5)
                + "BEGIN PRIVATE KEY"
                + ("-" * 5)
                + "\nprivate material\n"
            ),
        }
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, content in cases.items():
                (root / name).write_text(content, encoding="utf-8")

            findings = release_check.scan_candidate_tree(root, [])

        by_path = {
            item["path"]: item["kind"]
            for item in findings
        }
        self.assertEqual("absolute_home_path", by_path["users.txt"])
        self.assertEqual("absolute_home_path", by_path["home.txt"])
        self.assertEqual("windows_absolute_path", by_path["drive.txt"])
        self.assertEqual("unc_path", by_path["unc.txt"])
        self.assertEqual("home_expansion", by_path["tilde.txt"])
        self.assertEqual("secret_token", by_path["openai.txt"])
        self.assertEqual("secret_token", by_path["github.txt"])
        self.assertEqual("secret_token", by_path["aws.txt"])
        self.assertEqual("private_key", by_path["private-key.txt"])

    def test_release_scanner_flags_dotenv_and_oversized_public_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".env").write_text("SETTING=value\n", encoding="utf-8")
            (root / "oversized.bin").write_bytes(b"x" * (5 * 1024 * 1024 + 1))

            findings = release_check.scan_candidate_tree(root, [])

        self.assertEqual(
            {
                (".env", "dotenv_file"),
                ("oversized.bin", "oversized_file"),
            },
            {(item["path"], item["kind"]) for item in findings},
        )

    def test_release_scanner_excludes_only_declared_generated_locations(
        self,
    ) -> None:
        marker = "do-not-release"
        excluded = (
            ".git",
            ".venv",
            "build",
            "dist",
            ".release-preview",
            "__pycache__",
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for directory in excluded:
                candidate = root / directory / "private.txt"
                candidate.parent.mkdir()
                candidate.write_text(marker, encoding="utf-8")
            (root / "visible.txt").write_text(marker, encoding="utf-8")

            findings = release_check.scan_candidate_tree(root, [marker])

        self.assertEqual(
            [("visible.txt", "forbidden_term")],
            [(item["path"], item["kind"]) for item in findings],
        )

    def test_release_scanner_allows_manifest_declared_synthetic_images(
        self,
    ) -> None:
        relative_image = Path("examples/synthetic-case/declared.png")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / relative_image
            image.parent.mkdir(parents=True)
            image.write_bytes(
                b"\x00"
                + ("~" + "/").encode()
                + (b"x" * (5 * 1024 * 1024 + 1))
            )
            manifest = (
                root
                / "src"
                / "data_audit_toolkit"
                / "benchmark_data"
                / "manifest.sha256"
            )
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                ("0" * 64) + f"  {relative_image.as_posix()}\n",
                encoding="utf-8",
            )

            findings = release_check.scan_candidate_tree(root, [])

        self.assertEqual([], findings)

    def test_wheel_inspection_rejects_cache_and_unsafe_member_paths(self) -> None:
        absolute_member = "/" + "Users" + "/example/private.py"
        with tempfile.TemporaryDirectory() as temp:
            wheel = Path(temp) / "candidate.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("data_audit_toolkit/__init__.py", "")
                archive.writestr(
                    "data_audit_toolkit/__pycache__/module.pyc",
                    b"compiled",
                )
                archive.writestr(absolute_member, "private")
                archive.writestr(
                    "data_audit_toolkit/benchmark_data/only/expected.json",
                    "{}",
                )
                archive.writestr("tests/test_private.py", "private")

            findings = release_check.inspect_wheel_contents(wheel)

        self.assertEqual(
            {
                "benchmark_resource_mismatch",
                "cache_artifact",
                "unexpected_wheel_content",
                "unsafe_wheel_path",
            },
            {item["kind"] for item in findings},
        )

    def test_wheel_inspection_accepts_exact_canonical_benchmark_package(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            wheel = Path(temp) / "candidate.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("data_audit_toolkit/__init__.py", "")
                benchmark_source = (
                    ROOT / "src" / "data_audit_toolkit" / "benchmark_data"
                )
                for source in sorted(benchmark_source.rglob("*")):
                    if (
                        not source.is_file()
                        or "__pycache__" in source.parts
                        or source.suffix in {".pyc", ".pyo"}
                    ):
                        continue
                    archive.writestr(
                        "data_audit_toolkit/benchmark_data/"
                        + source.relative_to(benchmark_source).as_posix(),
                        source.read_bytes(),
                    )

            findings = release_check.inspect_wheel_contents(wheel)

        self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()
