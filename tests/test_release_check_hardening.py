from __future__ import annotations

import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

from scripts import release_check


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_SOURCE = ROOT / "src" / "data_audit_toolkit" / "benchmark_data"
FORBIDDEN_TEST_TERM = "private" + "_corpus"


def _benchmark_source_files() -> list[Path]:
    return sorted(
        candidate
        for candidate in BENCHMARK_SOURCE.rglob("*")
        if candidate.is_file()
        and "__pycache__" not in candidate.parts
        and candidate.suffix not in {".pyc", ".pyo"}
    )


def _add_tar_bytes(
    archive: tarfile.TarFile,
    name: str,
    payload: bytes,
    *,
    mode: int = 0o644,
) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = mode
    archive.addfile(member, io.BytesIO(payload))


def _write_canonical_wheel(
    destination: Path,
    *,
    omitted: str | None = None,
    replacement: tuple[str, bytes] | None = None,
) -> None:
    with zipfile.ZipFile(destination, "w") as archive:
        archive.writestr("data_audit_toolkit/__init__.py", "")
        for source in _benchmark_source_files():
            relative = source.relative_to(BENCHMARK_SOURCE).as_posix()
            if relative == omitted:
                continue
            archive.writestr(
                f"data_audit_toolkit/benchmark_data/{relative}",
                source.read_bytes(),
            )
        if replacement is not None:
            name, payload = replacement
            archive.writestr(
                f"data_audit_toolkit/benchmark_data/{name}",
                payload,
            )


def _write_canonical_sdist(
    destination: Path,
    *,
    omitted: str | None = None,
) -> None:
    prefix = "candidate-0.0.0"
    with tarfile.open(destination, "w:gz") as archive:
        _add_tar_bytes(archive, f"{prefix}/pyproject.toml", b"[build-system]\n")
        _add_tar_bytes(
            archive,
            f"{prefix}/src/data_audit_toolkit/__init__.py",
            b"",
        )
        for source in _benchmark_source_files():
            relative = source.relative_to(BENCHMARK_SOURCE).as_posix()
            if relative == omitted:
                continue
            _add_tar_bytes(
                archive,
                f"{prefix}/src/data_audit_toolkit/benchmark_data/{relative}",
                source.read_bytes(),
            )


def _git(repo: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
    )


def _initialize_git_repository(repo: Path) -> str:
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Release Test")
    _git(repo, "config", "user.email", "release-test@example.invalid")
    (repo / "tracked.txt").write_text("first\n", encoding="utf-8")
    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "-q", "-m", "initial")
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


class ReleaseScannerHardeningTests(unittest.TestCase):
    def test_package_file_symlink_is_rejected_before_target_bytes_are_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            root = workspace / "release"
            package = root / "src" / "data_audit_toolkit"
            package.mkdir(parents=True)
            outside = workspace / "outside.py"
            outside.write_text(
                "private" + "_corpus_payload = True\n",
                encoding="utf-8",
            )
            (package / "linked.py").symlink_to(outside)

            findings = release_check.scan_candidate_tree(
                root,
                [FORBIDDEN_TEST_TERM],
            )

        self.assertTrue(
            any(
                finding["kind"] == "symlink_entry"
                and finding["path"] == "src/data_audit_toolkit/linked.py"
                for finding in findings
            ),
            findings,
        )
        self.assertFalse(
            any(finding["kind"] == "forbidden_term" for finding in findings),
            findings,
        )

    def test_directory_symlink_is_rejected_and_not_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            root = workspace / "release"
            package = root / "src" / "data_audit_toolkit"
            package.mkdir(parents=True)
            outside = workspace / "outside"
            outside.mkdir()
            (outside / "secret.txt").write_text(
                "private" + "_corpus_payload\n",
                encoding="utf-8",
            )
            (package / "linked-directory").symlink_to(
                outside,
                target_is_directory=True,
            )

            findings = release_check.scan_candidate_tree(
                root,
                [FORBIDDEN_TEST_TERM],
            )

        self.assertTrue(
            any(
                finding["kind"] == "symlink_entry"
                and finding["path"]
                == "src/data_audit_toolkit/linked-directory"
                for finding in findings
            ),
            findings,
        )
        self.assertFalse(
            any(finding["kind"] == "forbidden_term" for finding in findings),
            findings,
        )

    def test_dangling_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "dangling").symlink_to(root / "does-not-exist")

            findings = release_check.scan_candidate_tree(
                root,
                [FORBIDDEN_TEST_TERM],
            )

        self.assertTrue(
            any(
                finding["kind"] == "symlink_entry"
                and finding["path"] == "dangling"
                for finding in findings
            ),
            findings,
        )

    def test_symlinked_image_manifest_is_not_read_to_exempt_content(self) -> None:
        relative_image = Path("examples/synthetic-case/declared.png")
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            root = workspace / "release"
            image = root / relative_image
            image.parent.mkdir(parents=True)
            image.write_bytes(
                ("~" + "/").encode()
                + b"x" * (release_check.MAX_PUBLIC_FILE_BYTES + 1)
            )
            outside_manifest = workspace / "outside-manifest.sha256"
            outside_manifest.write_text(
                ("0" * 64) + f"  {relative_image.as_posix()}\n",
                encoding="utf-8",
            )
            manifest = (
                root
                / "src"
                / "data_audit_toolkit"
                / "benchmark_data"
                / "manifest.sha256"
            )
            manifest.parent.mkdir(parents=True)
            manifest.symlink_to(outside_manifest)

            findings = release_check.scan_candidate_tree(
                root,
                [FORBIDDEN_TEST_TERM],
            )

        self.assertTrue(
            any(
                finding["kind"] == "symlink_entry"
                and finding["path"]
                == "src/data_audit_toolkit/benchmark_data/manifest.sha256"
                for finding in findings
            ),
            findings,
        )
        self.assertTrue(
            any(
                finding["kind"] == "oversized_file"
                and finding["path"] == relative_image.as_posix()
                for finding in findings
            ),
            findings,
        )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO support")
    def test_non_regular_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            fifo = root / "release-pipe"
            os.mkfifo(fifo)

            findings = release_check.scan_candidate_tree(
                root,
                [FORBIDDEN_TEST_TERM],
            )

        self.assertTrue(
            any(
                finding["kind"] == "non_regular_entry"
                and finding["path"] == "release-pipe"
                for finding in findings
            ),
            findings,
        )

    def test_missing_scan_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "missing"

            findings = release_check.scan_candidate_tree(
                root,
                [FORBIDDEN_TEST_TERM],
            )

        self.assertTrue(
            any(finding["kind"] == "traversal_error" for finding in findings),
            findings,
        )

    def test_release_only_directories_are_excluded_only_at_repository_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for name in (".git", ".venv", "build", "dist", ".release-preview"):
                directory = root / name
                directory.mkdir()
                (directory / "ignored.txt").write_text(
                    "private" + "_corpus_payload\n",
                    encoding="utf-8",
                )
            nested_package = root / "src" / "data_audit_toolkit"
            for name in ("build", "dist"):
                directory = nested_package / name
                directory.mkdir(parents=True)
                (directory / "must-scan.txt").write_text(
                    "private" + "_corpus_payload\n",
                    encoding="utf-8",
                )
            nested_cache = nested_package / "nested" / "__pycache__"
            nested_cache.mkdir(parents=True)
            (nested_cache / "ignored.pyc").write_text(
                "private" + "_corpus_payload\n",
                encoding="utf-8",
            )

            findings = release_check.scan_candidate_tree(
                root,
                [FORBIDDEN_TEST_TERM],
            )

        forbidden_paths = {
            finding["path"]
            for finding in findings
            if finding["kind"] == "forbidden_term"
        }
        self.assertEqual(
            forbidden_paths,
            {
                "src/data_audit_toolkit/build/must-scan.txt",
                "src/data_audit_toolkit/dist/must-scan.txt",
            },
        )

    def test_encrypted_and_bounded_private_key_headers_are_detected(self) -> None:
        begin = "-" * 5 + "BEGIN "
        end = "PRIVATE KEY" + "-" * 5
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "encrypted.pem").write_text(
                begin + "ENCRYPTED " + end + "\n",
                encoding="utf-8",
            )
            (root / "variant.pem").write_text(
                begin + "VENDOR WRAPPED " + end + "\n",
                encoding="utf-8",
            )

            findings = release_check.scan_candidate_tree(
                root,
                [FORBIDDEN_TEST_TERM],
            )

        private_key_paths = {
            finding["path"]
            for finding in findings
            if finding["kind"] == "private_key"
        }
        self.assertEqual(private_key_paths, {"encrypted.pem", "variant.pem"})


class ReleaseArtifactContractTests(unittest.TestCase):
    def test_wheel_requires_exact_canonical_benchmark_resources(self) -> None:
        omitted = "duplicate-columns/expected.json"
        replacement = (
            "replacement-case/expected.json",
            (BENCHMARK_SOURCE / omitted).read_bytes(),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            wheel = Path(temporary_directory) / "candidate.whl"
            _write_canonical_wheel(
                wheel,
                omitted=omitted,
                replacement=replacement,
            )

            findings = release_check.inspect_wheel_contents(wheel, root=ROOT)

        self.assertTrue(
            any(
                finding["kind"] == "benchmark_resource_mismatch"
                for finding in findings
            ),
            findings,
        )

    def test_canonical_wheel_resource_contract_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            wheel = Path(temporary_directory) / "candidate.whl"
            _write_canonical_wheel(wheel)

            findings = release_check.inspect_wheel_contents(wheel, root=ROOT)

        self.assertEqual(findings, [])

    def test_wheel_rejects_test_content_inside_package(self) -> None:
        hidden_test_paths = (
            "data_audit_toolkit/tests/test_hidden.py",
            "data_audit_toolkit/test_hidden.py",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            wheel = Path(temporary_directory) / "candidate.whl"
            _write_canonical_wheel(wheel)
            with zipfile.ZipFile(wheel, "a") as archive:
                for path in hidden_test_paths:
                    archive.writestr(path, "def test_hidden(): pass\n")

            findings = release_check.inspect_wheel_contents(wheel, root=ROOT)

        test_paths = {
            finding["path"]
            for finding in findings
            if finding["kind"] == "test_content"
        }
        self.assertEqual(test_paths, set(hidden_test_paths))

    def test_wheel_rejects_private_directories_inside_package(self) -> None:
        hidden_private_paths = (
            "data_audit_toolkit/.git/config",
            "data_audit_toolkit/.venv/lib/hidden.py",
            "data_audit_toolkit/.release-preview/draft.py",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            wheel = Path(temporary_directory) / "candidate.whl"
            _write_canonical_wheel(wheel)
            with zipfile.ZipFile(wheel, "a") as archive:
                for path in hidden_private_paths:
                    archive.writestr(path, "hidden\n")

            findings = release_check.inspect_wheel_contents(wheel, root=ROOT)

        private_paths = {
            finding["path"]
            for finding in findings
            if finding["kind"] == "private_wheel_file"
        }
        self.assertEqual(private_paths, set(hidden_private_paths))

    def test_sdist_rejects_unsafe_links_caches_private_and_test_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            sdist = Path(temporary_directory) / "candidate.tar.gz"
            prefix = "candidate-0.0.0"
            with tarfile.open(sdist, "w:gz") as archive:
                _add_tar_bytes(
                    archive,
                    "/absolute.txt",
                    b"unsafe\n",
                )
                _add_tar_bytes(
                    archive,
                    f"{prefix}/../traversal.txt",
                    b"unsafe\n",
                )
                link = tarfile.TarInfo(
                    f"{prefix}/src/data_audit_toolkit/linked.py"
                )
                link.type = tarfile.SYMTYPE
                link.linkname = "../../outside.py"
                archive.addfile(link)
                _add_tar_bytes(
                    archive,
                    f"{prefix}/src/data_audit_toolkit/__pycache__/cached.pyc",
                    b"cached\n",
                )
                _add_tar_bytes(
                    archive,
                    f"{prefix}/.env",
                    b"TOKEN=secret\n",
                )
                _add_tar_bytes(
                    archive,
                    f"{prefix}/tests/test_private.py",
                    b"def test_private(): pass\n",
                )

            findings = release_check.inspect_sdist_contents(sdist, root=ROOT)

        finding_kinds = {finding["kind"] for finding in findings}
        self.assertTrue(
            {
                "unsafe_archive_path",
                "archive_link",
                "cache_artifact",
                "private_archive_file",
                "test_content",
                "benchmark_resource_mismatch",
            }.issubset(finding_kinds),
            findings,
        )

    def test_sdist_missing_canonical_benchmark_resource_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            sdist = Path(temporary_directory) / "candidate.tar.gz"
            _write_canonical_sdist(
                sdist,
                omitted="duplicate-columns/expected.json",
            )

            findings = release_check.inspect_sdist_contents(sdist, root=ROOT)

        self.assertTrue(
            any(
                finding["kind"] == "benchmark_resource_mismatch"
                for finding in findings
            ),
            findings,
        )

    def test_canonical_sdist_resource_contract_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            sdist = Path(temporary_directory) / "candidate.tar.gz"
            _write_canonical_sdist(sdist)

            findings = release_check.inspect_sdist_contents(sdist, root=ROOT)

        self.assertEqual(findings, [])


class InstalledEnvironmentIsolationTests(unittest.TestCase):
    def test_external_python_source_variables_are_scrubbed(self) -> None:
        injected = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": "/tmp/injected-source",
            "PYTHONHOME": "/tmp/injected-home",
            "PYTHONSTARTUP": "/tmp/injected-startup.py",
            "PYTHONUSERBASE": "/tmp/injected-userbase",
            "PYTHONINSPECT": "1",
            "PYTHONWARNINGS": "ignore",
            "VIRTUAL_ENV": "/tmp/injected-venv",
            "__PYVENV_LAUNCHER__": "/tmp/injected-python",
        }

        scrubbed = release_check.scrubbed_python_environment(injected)

        self.assertEqual(scrubbed["PYTHONNOUSERSITE"], "1")
        self.assertEqual(scrubbed["PYTHONSAFEPATH"], "1")
        for variable in injected:
            if variable != "PATH":
                self.assertNotIn(variable, scrubbed)

    def test_installed_import_ignores_callers_pythonpath_source_tree(self) -> None:
        injected = dict(os.environ)
        injected["PYTHONPATH"] = str(ROOT / "src")
        with tempfile.TemporaryDirectory() as temporary_directory:
            process = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path; "
                        "import data_audit_toolkit; "
                        "print(Path(data_audit_toolkit.__file__).resolve())"
                    ),
                ],
                cwd=temporary_directory,
                env=release_check.scrubbed_python_environment(injected),
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(process.returncode, 0, process.stderr)
        imported_path = Path(process.stdout.strip())
        self.assertFalse(
            imported_path.is_relative_to((ROOT / "src").resolve()),
            imported_path,
        )


class SkillValidatorHardeningTests(unittest.TestCase):
    def test_skill_name_must_be_one_safe_grammar_component(self) -> None:
        invalid_names = (
            "../escape",
            "bad/name",
            ".",
            "Uppercase",
            "double--dash",
            "",
        )
        for name in invalid_names:
            with self.subTest(name=name):
                self.assertFalse(release_check.is_safe_skill_name(name))
        self.assertTrue(release_check.is_safe_skill_name("data-audit-toolkit"))

    def test_validation_copy_cannot_escape_temp_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            root = workspace / "release"
            root.mkdir()
            (root / "SKILL.md").write_text(
                "---\nname: ../escape\ndescription: invalid\n---\n",
                encoding="utf-8",
            )
            validation_root = workspace / "validation"
            validation_root.mkdir()

            with self.assertRaises(ValueError):
                release_check.prepare_skill_validation_copy(
                    root,
                    validation_root,
                )

            self.assertFalse((workspace / "escape").exists())

    def test_validation_copy_preserves_exact_skill_bytes(self) -> None:
        skill_bytes = (
            b"---\nname: data-audit-toolkit\n"
            b"description: Exact bytes are required.\n---\n"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            root = workspace / "release"
            root.mkdir()
            (root / "SKILL.md").write_bytes(skill_bytes)
            validation_root = workspace / "validation"
            validation_root.mkdir()

            copied = release_check.prepare_skill_validation_copy(
                root,
                validation_root,
            )

            self.assertTrue(copied.is_relative_to(validation_root.resolve()))
            self.assertEqual(copied.read_bytes(), skill_bytes)

    def test_arbitrary_validator_executable_is_not_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory) / "skills-ref"
            candidate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            candidate.chmod(candidate.stat().st_mode | stat.S_IXUSR)

            trusted = release_check.is_trusted_validator_executable(
                candidate,
                python_executable=Path(sys.executable),
            )

        self.assertFalse(trusted)

    def test_validator_beside_virtual_environment_python_is_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            binaries = Path(temporary_directory) / "bin"
            binaries.mkdir()
            virtual_python = binaries / "python"
            virtual_python.symlink_to(Path(sys.executable))
            validator = binaries / "skills-ref"
            validator.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            validator.chmod(validator.stat().st_mode | stat.S_IXUSR)

            trusted = release_check.is_trusted_validator_executable(
                validator,
                python_executable=virtual_python,
            )

        self.assertTrue(trusted)

    def test_pep_610_provenance_requires_exact_pinned_commit(self) -> None:
        expected = {
            "url": "https://github.com/agentskills/agentskills.git",
            "subdirectory": "skills-ref",
            "vcs_info": {
                "vcs": "git",
                "requested_revision": release_check.SKILLS_REF_COMMIT,
                "commit_id": release_check.SKILLS_REF_COMMIT,
            },
        }
        self.assertEqual(
            release_check.skills_ref_provenance_findings(expected),
            [],
        )

        wrong_commit = json.loads(json.dumps(expected))
        wrong_commit["vcs_info"]["commit_id"] = "0" * 40
        self.assertTrue(
            release_check.skills_ref_provenance_findings(wrong_commit),
        )


class ReleaseStateAndFailureTests(unittest.TestCase):
    def test_build_uses_fresh_commit_snapshot_after_successful_mutating_test(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            root.mkdir()
            _initialize_git_repository(root)
            package_file = root / "src" / "data_audit_toolkit" / "sentinel.py"
            package_file.parent.mkdir(parents=True)
            package_file.write_bytes(b"captured bytes\n")
            _git(root, "add", package_file.relative_to(root).as_posix())
            _git(root, "commit", "-q", "-m", "add captured package bytes")
            observed_build_bytes: list[bytes] = []

            def controlled_process(
                arguments: list[str] | tuple[str, ...],
                *,
                cwd: Path,
                env: dict[str, str] | None = None,
            ) -> subprocess.CompletedProcess[str]:
                command = list(arguments)
                if "unittest" in command:
                    (
                        cwd / "src" / "data_audit_toolkit" / "sentinel.py"
                    ).write_bytes(b"mutated by successful test\n")
                    return subprocess.CompletedProcess(command, 0, "", "")
                if any(
                    argument.endswith("check_benchmark_suite.py")
                    for argument in command
                ):
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        json.dumps({"case_count": 19, "failures": {}}),
                        "",
                    )
                if command[-2:] == ["-m", "build"]:
                    observed_build_bytes.append(
                        (
                            cwd
                            / "src"
                            / "data_audit_toolkit"
                            / "sentinel.py"
                        ).read_bytes()
                    )
                    return subprocess.CompletedProcess(
                        command,
                        1,
                        "",
                        "controlled stop after observing build input",
                    )
                return release_check.run_process(command, cwd=cwd, env=env)

            with mock.patch.object(
                release_check,
                "_run_process",
                side_effect=controlled_process,
            ):
                summary = release_check.run_release_checks(root, [])

        self.assertEqual(observed_build_bytes, [b"captured bytes\n"])
        self.assertEqual(summary["gates"]["unit_tests"]["status"], "passed")
        self.assertEqual(summary["gates"]["benchmark"]["status"], "passed")
        self.assertEqual(summary["gates"]["build"]["status"], "failed")

    def test_package_symlink_stops_release_before_build_regression(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            root = workspace / "repo"
            root.mkdir()
            _initialize_git_repository(root)
            outside = workspace / "outside.py"
            outside.write_text("must never be packaged\n", encoding="utf-8")
            package = root / "src" / "data_audit_toolkit"
            package.mkdir(parents=True)
            (package / "linked.py").symlink_to(outside)
            _git(root, "add", "src/data_audit_toolkit/linked.py")
            _git(root, "commit", "-q", "-m", "add unsafe package link")

            summary = release_check.run_release_checks(root, [])

        self.assertEqual(summary["gates"]["snapshot"]["status"], "failed")
        self.assertIn(
            "unsafe Git archive member",
            summary["gates"]["snapshot"]["detail"],
        )
        self.assertEqual(summary["gates"]["build"]["status"], "not_run")

    def test_dirty_start_fails_before_snapshot_or_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _initialize_git_repository(root)
            (root / "untracked.txt").write_text("dirty\n", encoding="utf-8")

            summary = release_check.run_release_checks(root, [])

        self.assertEqual(summary["gates"]["initial_git"]["status"], "failed")
        self.assertEqual(summary["gates"]["snapshot"]["status"], "not_run")
        self.assertEqual(summary["gates"]["build"]["status"], "not_run")

    def test_head_change_is_detected_against_captured_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            expected_head = _initialize_git_repository(root)
            (root / "tracked.txt").write_text("second\n", encoding="utf-8")
            _git(root, "add", "tracked.txt")
            _git(root, "commit", "-q", "-m", "second")

            matches, detail = release_check.git_head_matches(
                root,
                expected_head,
            )

        self.assertFalse(matches)
        self.assertIn(expected_head, detail)

    def test_snapshot_contains_only_bytes_from_captured_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            root.mkdir()
            head = _initialize_git_repository(root)
            (root / "untracked.txt").write_text("not committed\n", encoding="utf-8")
            destination = Path(temporary_directory) / "snapshot"

            snapshot = release_check.create_release_snapshot(
                root,
                head,
                destination,
            )
            tracked_text = (snapshot / "tracked.txt").read_text()
            untracked_exists = (snapshot / "untracked.txt").exists()

        self.assertEqual(tracked_text, "first\n")
        self.assertFalse(untracked_exists)

    def test_missing_process_becomes_nonzero_result_instead_of_exception(self) -> None:
        result = release_check.run_process(
            ["/definitely/missing/release-check-command"],
            cwd=ROOT,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("process setup failed", result.stderr)

    def test_cleanup_symlink_is_a_failed_cleanup_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            root = workspace / "release"
            root.mkdir()
            outside = workspace / "outside"
            outside.mkdir()
            (root / "build").symlink_to(outside, target_is_directory=True)

            findings = release_check.remove_generated_artifacts(root)
            outside_survived = outside.exists()

        self.assertTrue(
            any(finding["kind"] == "cleanup_failure" for finding in findings),
            findings,
        )
        self.assertTrue(outside_survived)

    def test_main_emits_exactly_one_complete_json_summary_on_setup_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root_file = Path(temporary_directory) / "not-a-directory"
            root_file.write_text("not a repository\n", encoding="utf-8")
            output = io.StringIO()

            exit_code = release_check.main(
                [],
                root=root_file,
                output=output,
            )

        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1, lines)
        payload = json.loads(lines[0])
        self.assertEqual(exit_code, 1)
        self.assertEqual(set(payload["gates"]), set(release_check.GATE_NAMES))
        self.assertEqual(payload["status"], "failed")


if __name__ == "__main__":
    unittest.main()
