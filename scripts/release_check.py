#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, TextIO


ROOT = Path(__file__).resolve().parents[1]
ROOT_EXCLUDED_PATHS = frozenset(
    {".git", ".venv", "build", "dist", ".release-preview"}
)
CACHE_DIRECTORY_NAME = "__pycache__"
MAX_PUBLIC_FILE_BYTES = 5 * 1024 * 1024
SYNTHETIC_MANIFEST = Path(
    "src/data_audit_toolkit/benchmark_data/manifest.sha256"
)
SYNTHETIC_IMAGE_ROOTS = (
    "examples/synthetic-case/",
    "src/data_audit_toolkit/benchmark_data/",
)
IMAGE_SUFFIXES = frozenset(
    {".bmp", ".gif", ".jpeg", ".jpg", ".png", ".tif", ".tiff"}
)
SKILLS_REF_COMMIT = "38a2ff82958afee88dadf4831509e6f7e9d8ef4e"
SKILLS_REF_URL = "https://github.com/agentskills/agentskills.git"
SKILL_NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PYTHON_ENVIRONMENT_VARIABLES = frozenset(
    {
        "PYTHONEXECUTABLE",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONWARNINGS",
        "VIRTUAL_ENV",
        "__PYVENV_LAUNCHER__",
    }
)
GATE_NAMES = (
    "initial_git",
    "snapshot",
    "public_hygiene",
    "unit_tests",
    "benchmark",
    "build",
    "wheel_contents",
    "sdist_contents",
    "twine",
    "agent_skill",
    "wheel_install",
    "wheel_version",
    "wheel_benchmark",
    "wheel_scan",
    "cleanup",
    "diff_check",
    "head_unchanged",
    "status_clean",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the complete local release validation suite.",
    )
    parser.add_argument(
        "--forbid-term",
        action="append",
        default=[],
        metavar="TERM",
        help="Reject TERM in candidate public filenames or file contents. Repeatable.",
    )
    return parser


def _is_excluded_relative_path(relative: Path) -> bool:
    return (
        relative.as_posix() in ROOT_EXCLUDED_PATHS
        or CACHE_DIRECTORY_NAME in relative.parts
    )


def _candidate_files(
    root: Path,
    add_finding: Any,
) -> list[tuple[Path, str]]:
    candidates: list[tuple[Path, str]] = []
    traversal_errors: list[OSError] = []

    def record_walk_error(error: OSError) -> None:
        traversal_errors.append(error)

    try:
        root_metadata = root.lstat()
        if stat.S_ISLNK(root_metadata.st_mode):
            add_finding(".", "symlink_entry", "release root")
            return []
        if not stat.S_ISDIR(root_metadata.st_mode):
            add_finding(".", "traversal_error", "release root is not a directory")
            return []
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        add_finding(".", "traversal_error", type(error).__name__)
        return []

    try:
        walker = os.walk(
            resolved_root,
            topdown=True,
            followlinks=False,
            onerror=record_walk_error,
        )
        for directory, directory_names, file_names in walker:
            base = Path(directory)
            retained_directories: list[str] = []
            for name in sorted(directory_names):
                candidate = base / name
                try:
                    relative_path = candidate.relative_to(resolved_root)
                except ValueError:
                    add_finding(str(candidate), "outside_release_root", "directory")
                    continue
                if _is_excluded_relative_path(relative_path):
                    continue
                relative = relative_path.as_posix()
                try:
                    metadata = candidate.lstat()
                except OSError as error:
                    add_finding(relative, "traversal_error", type(error).__name__)
                    continue
                if stat.S_ISLNK(metadata.st_mode):
                    add_finding(relative, "symlink_entry", "directory")
                    continue
                if not stat.S_ISDIR(metadata.st_mode):
                    add_finding(relative, "non_regular_entry", "directory entry")
                    continue
                retained_directories.append(name)
            directory_names[:] = retained_directories

            for name in sorted(file_names):
                candidate = base / name
                try:
                    relative_path = candidate.relative_to(resolved_root)
                except ValueError:
                    add_finding(str(candidate), "outside_release_root", "file")
                    continue
                if _is_excluded_relative_path(relative_path):
                    continue
                relative = relative_path.as_posix()
                try:
                    metadata = candidate.lstat()
                except OSError as error:
                    add_finding(relative, "traversal_error", type(error).__name__)
                    continue
                if stat.S_ISLNK(metadata.st_mode):
                    add_finding(relative, "symlink_entry", "file")
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    add_finding(relative, "non_regular_entry", "file entry")
                    continue
                try:
                    resolved_candidate = candidate.resolve(strict=True)
                    resolved_candidate.relative_to(resolved_root)
                except (OSError, ValueError) as error:
                    add_finding(relative, "outside_release_root", type(error).__name__)
                    continue
                candidates.append((candidate, relative))
    except OSError as error:
        traversal_errors.append(error)

    for error in traversal_errors:
        filename = Path(error.filename).as_posix() if error.filename else "."
        try:
            relative = Path(filename).relative_to(resolved_root).as_posix()
        except ValueError:
            relative = filename
        add_finding(relative, "traversal_error", type(error).__name__)
    return sorted(candidates, key=lambda item: item[1])


def _declared_synthetic_images(root: Path) -> frozenset[str]:
    manifest = root / SYNTHETIC_MANIFEST
    declared: set[str] = set()
    try:
        metadata = manifest.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            return frozenset()
        manifest.resolve(strict=True).relative_to(root.resolve(strict=True))
        open_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            open_flags |= os.O_NOFOLLOW
        descriptor = os.open(manifest, open_flags)
        with os.fdopen(descriptor, "rb") as source:
            live_metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(live_metadata.st_mode):
                return frozenset()
            payload = source.read(MAX_PUBLIC_FILE_BYTES + 1)
        if len(payload) > MAX_PUBLIC_FILE_BYTES:
            return frozenset()
        lines = payload.decode("utf-8").splitlines()
    except (OSError, UnicodeError, ValueError):
        return frozenset()
    for line in lines:
        if "  " not in line:
            continue
        relative = line.split("  ", 1)[1]
        if (
            relative.startswith(SYNTHETIC_IMAGE_ROOTS)
            and Path(relative).suffix.casefold() in IMAGE_SUFFIXES
        ):
            declared.add(relative)
    return frozenset(declared)


def _sensitive_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    users_prefix = "/" + "Users" + "/"
    home_prefix = "/" + "home" + "/"
    home_pattern = (
        r"(?P<absolute_home_path>(?:"
        + re.escape(users_prefix)
        + "|"
        + re.escape(home_prefix)
        + r")[A-Za-z0-9._-]+/)"
    )
    separator = chr(92)
    windows_separator = "[" + re.escape(separator) + "/]"
    unc_prefix = re.escape(separator * 2)
    unc_separator = re.escape(separator)
    private_key_begin = ("-" * 5) + "BEGIN "
    private_key_end = "PRIVATE KEY" + ("-" * 5)
    token_prefixes = (
        re.escape("s" + "k-") + r"[A-Za-z0-9_-]{20,}",
        re.escape("g" + "h") + r"[opusr]_[A-Za-z0-9]{30,}",
        re.escape("A" + "K" + "I" + "A") + r"[A-Z0-9]{16}",
        re.escape("x" + "ox") + r"[baprs]-[A-Za-z0-9-]{10,}",
        re.escape("A" + "Iza") + r"[A-Za-z0-9_-]{30,}",
    )
    return (
        ("absolute_home_path", re.compile(home_pattern)),
        (
            "windows_absolute_path",
            re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:" + windows_separator),
        ),
        (
            "unc_path",
            re.compile(
                unc_prefix
                + r"[A-Za-z0-9._-]+"
                + unc_separator
                + r"[A-Za-z0-9.$_-]+"
            ),
        ),
        (
            "home_expansion",
            re.compile(r"(?<![A-Za-z0-9._-])" + re.escape("~" + "/")),
        ),
        (
            "secret_token",
            re.compile(r"(?:" + "|".join(token_prefixes) + r")"),
        ),
        (
            "private_key",
            re.compile(
                re.escape(private_key_begin)
                + r"(?:[A-Z0-9][A-Z0-9 -]{0,31} )?"
                + re.escape(private_key_end)
            ),
        ),
    )


def scan_candidate_tree(
    root: Path,
    forbidden_terms: Sequence[str],
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(path: str, kind: str, detail: str) -> None:
        key = (path, kind, detail)
        if key in seen:
            return
        seen.add(key)
        findings.append({"path": path, "kind": kind, "detail": detail})

    candidate_files = _candidate_files(root, add)
    try:
        resolved_root = root.resolve(strict=True)
    except OSError:
        return findings
    declared_images = _declared_synthetic_images(resolved_root)
    patterns = _sensitive_patterns()
    normalized_terms = tuple(
        (term, term.casefold())
        for term in forbidden_terms
        if term
    )

    for candidate, relative in candidate_files:
        relative_folded = relative.casefold()
        if candidate.name == ".env" or candidate.name.startswith(".env."):
            add(relative, "dotenv_file", "filename")
        try:
            open_flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                open_flags |= os.O_NOFOLLOW
            descriptor = os.open(candidate, open_flags)
            with os.fdopen(descriptor, "rb") as source:
                metadata = os.fstat(source.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    add(relative, "non_regular_entry", "changed before read")
                    continue
                content = source.read(MAX_PUBLIC_FILE_BYTES + 1)
                size = metadata.st_size
        except OSError as error:
            add(relative, "unreadable_file", type(error).__name__)
            continue
        try:
            candidate.resolve(strict=True).relative_to(resolved_root)
        except (OSError, ValueError) as error:
            add(relative, "outside_release_root", type(error).__name__)
            continue
        if size > MAX_PUBLIC_FILE_BYTES and relative not in declared_images:
            add(relative, "oversized_file", "size")
        text = (
            ""
            if relative in declared_images
            else content.decode("utf-8", errors="ignore")
        )
        text_folded = text.casefold()
        for term, folded in normalized_terms:
            if folded in relative_folded:
                add(relative, "forbidden_term", f"filename:{term}")
            if folded in text_folded:
                add(relative, "forbidden_term", f"content:{term}")
        for kind, pattern in patterns:
            if pattern.search(relative):
                add(relative, kind, "filename")
            if pattern.search(text):
                add(relative, kind, "content")
    return findings


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _benchmark_resource_contract(
    root: Path,
    *,
    archive_prefix: str,
) -> tuple[dict[str, str], list[dict[str, str]]]:
    findings: list[dict[str, str]] = []
    benchmark_root = (
        root / "src" / "data_audit_toolkit" / "benchmark_data"
    )
    manifest = benchmark_root / "manifest.sha256"
    declared: dict[str, str] = {}
    try:
        for line_number, line in enumerate(
            manifest.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            digest, separator, source_relative = line.partition("  ")
            if not separator:
                findings.append(
                    {
                        "path": SYNTHETIC_MANIFEST.as_posix(),
                        "kind": "benchmark_source_contract",
                        "detail": f"invalid manifest line {line_number}",
                    }
                )
                continue
            prefix = "src/data_audit_toolkit/benchmark_data/"
            if source_relative.startswith(prefix):
                resource_relative = source_relative[len(prefix):]
                if (
                    not re.fullmatch(r"[0-9a-f]{64}", digest)
                    or not resource_relative
                ):
                    findings.append(
                        {
                            "path": SYNTHETIC_MANIFEST.as_posix(),
                            "kind": "benchmark_source_contract",
                            "detail": f"invalid benchmark line {line_number}",
                        }
                    )
                    continue
                declared[resource_relative] = digest
    except (OSError, UnicodeError) as error:
        return (
            {},
            [
                {
                    "path": SYNTHETIC_MANIFEST.as_posix(),
                    "kind": "benchmark_source_contract",
                    "detail": type(error).__name__,
                }
            ],
        )

    actual_resources: dict[str, str] = {}
    try:
        for source in sorted(benchmark_root.rglob("*")):
            relative = source.relative_to(benchmark_root)
            if (
                CACHE_DIRECTORY_NAME in relative.parts
                or source.suffix.casefold() in {".pyc", ".pyo"}
            ):
                continue
            metadata = source.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
            ):
                findings.append(
                    {
                        "path": source.relative_to(root).as_posix(),
                        "kind": "benchmark_source_contract",
                        "detail": "non-regular benchmark resource",
                    }
                )
                continue
            actual_resources[relative.as_posix()] = _sha256(source.read_bytes())
    except OSError as error:
        findings.append(
            {
                "path": benchmark_root.relative_to(root).as_posix(),
                "kind": "benchmark_source_contract",
                "detail": type(error).__name__,
            }
        )
        return {}, findings

    manifest_resources = {
        name: digest
        for name, digest in actual_resources.items()
        if name not in {"__init__.py", "manifest.sha256"}
    }
    if set(declared) != set(manifest_resources):
        findings.append(
            {
                "path": SYNTHETIC_MANIFEST.as_posix(),
                "kind": "benchmark_source_contract",
                "detail": (
                    "manifest resource set differs from benchmark source: "
                    f"missing={sorted(set(manifest_resources) - set(declared))}; "
                    f"unexpected={sorted(set(declared) - set(manifest_resources))}"
                ),
            }
        )
    for relative in sorted(set(declared) & set(manifest_resources)):
        if declared[relative] != manifest_resources[relative]:
            findings.append(
                {
                    "path": f"src/data_audit_toolkit/benchmark_data/{relative}",
                    "kind": "benchmark_source_contract",
                    "detail": "manifest digest does not match source bytes",
                }
            )

    contract = {
        archive_prefix + relative: digest
        for relative, digest in actual_resources.items()
    }
    return contract, findings


def _unsafe_archive_name(name: str) -> bool:
    separator = chr(92)
    parts = PurePosixPath(name).parts
    return bool(
        not name
        or name.startswith("/")
        or name.startswith(separator * 2)
        or re.match(
            r"^[A-Za-z]:" + "[" + re.escape(separator) + "/]",
            name,
        )
        or separator in name
        or ".." in parts
    )


def _benchmark_contract_finding(
    archive_name: str,
    expected: Mapping[str, str],
    actual: Mapping[str, str],
) -> dict[str, str] | None:
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    changed = sorted(
        name
        for name in set(expected) & set(actual)
        if expected[name] != actual[name]
    )
    if not (missing or unexpected or changed):
        return None
    return {
        "path": archive_name,
        "kind": "benchmark_resource_mismatch",
        "detail": (
            f"missing={missing}; unexpected={unexpected}; changed={changed}"
        ),
    }


def inspect_wheel_contents(
    wheel: Path,
    *,
    root: Path = ROOT,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    expected, contract_findings = _benchmark_resource_contract(
        root,
        archive_prefix="data_audit_toolkit/benchmark_data/",
    )
    findings.extend(contract_findings)
    benchmark_resources: dict[str, str] = {}
    seen_names: set[str] = set()
    try:
        with zipfile.ZipFile(wheel) as archive:
            members = sorted(archive.infolist(), key=lambda member: member.filename)
            for member in members:
                name = member.filename
                parts = PurePosixPath(name).parts
                if name in seen_names:
                    findings.append(
                        {
                            "path": name,
                            "kind": "duplicate_archive_member",
                            "detail": "wheel contains duplicate path",
                        }
                    )
                seen_names.add(name)
                if _unsafe_archive_name(name):
                    findings.append(
                        {
                            "path": name,
                            "kind": "unsafe_wheel_path",
                            "detail": "absolute, parent, or non-portable path",
                        }
                    )
                member_mode = member.external_attr >> 16
                if stat.S_ISLNK(member_mode):
                    findings.append(
                        {
                            "path": name,
                            "kind": "archive_link",
                            "detail": "wheel symlink",
                        }
                    )
                if (
                    CACHE_DIRECTORY_NAME in parts
                    or name.casefold().endswith((".pyc", ".pyo"))
                ):
                    findings.append(
                        {
                            "path": name,
                            "kind": "cache_artifact",
                            "detail": "generated bytecode",
                        }
                    )
                if any(
                    part == ".env" or part.startswith(".env.")
                    for part in parts
                ):
                    findings.append(
                        {
                            "path": name,
                            "kind": "private_wheel_file",
                            "detail": "dotenv file",
                        }
                    )
                if parts:
                    top_level = parts[0]
                    package_parts = parts[1:]
                    if top_level == "data_audit_toolkit":
                        if (
                            "tests" in package_parts
                            or any(
                                part.startswith("test_")
                                for part in package_parts
                            )
                        ):
                            findings.append(
                                {
                                    "path": name,
                                    "kind": "test_content",
                                    "detail": "tests are excluded from release wheels",
                                }
                            )
                        if any(
                            part in {".git", ".venv", ".release-preview"}
                            for part in package_parts
                        ):
                            findings.append(
                                {
                                    "path": name,
                                    "kind": "private_wheel_file",
                                    "detail": "private checkout content",
                                }
                            )
                    allowed = (
                        top_level == "data_audit_toolkit"
                        or (
                            top_level.startswith("data_audit_toolkit-")
                            and top_level.endswith(".dist-info")
                        )
                    )
                    if not allowed:
                        findings.append(
                            {
                                "path": name,
                                "kind": "unexpected_wheel_content",
                                "detail": "outside package or metadata",
                            }
                        )
                if name.startswith(
                    "data_audit_toolkit/benchmark_data/"
                ) and not name.endswith("/"):
                    try:
                        benchmark_resources[name] = _sha256(archive.read(member))
                    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                        findings.append(
                            {
                                "path": name,
                                "kind": "invalid_wheel",
                                "detail": type(error).__name__,
                            }
                        )
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        return [
            {
                "path": wheel.name,
                "kind": "invalid_wheel",
                "detail": type(error).__name__,
            }
        ]

    mismatch = _benchmark_contract_finding(
        wheel.name,
        expected,
        benchmark_resources,
    )
    if mismatch:
        findings.append(mismatch)
    return findings


def inspect_sdist_contents(
    sdist: Path,
    *,
    root: Path = ROOT,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    expected, contract_findings = _benchmark_resource_contract(
        root,
        archive_prefix="src/data_audit_toolkit/benchmark_data/",
    )
    findings.extend(contract_findings)
    benchmark_resources: dict[str, str] = {}
    archive_roots: set[str] = set()
    seen_names: set[str] = set()
    try:
        with tarfile.open(sdist, "r:*") as archive:
            for member in sorted(archive.getmembers(), key=lambda item: item.name):
                name = member.name
                parts = PurePosixPath(name).parts
                unsafe = _unsafe_archive_name(name)
                if unsafe:
                    findings.append(
                        {
                            "path": name,
                            "kind": "unsafe_archive_path",
                            "detail": "absolute, parent, or non-portable path",
                        }
                    )
                if name in seen_names:
                    findings.append(
                        {
                            "path": name,
                            "kind": "duplicate_archive_member",
                            "detail": "sdist contains duplicate path",
                        }
                    )
                seen_names.add(name)
                if parts and not unsafe:
                    archive_roots.add(parts[0])
                relative_parts = parts[1:] if len(parts) > 1 else ()
                relative = "/".join(relative_parts)
                if member.issym() or member.islnk():
                    findings.append(
                        {
                            "path": name,
                            "kind": "archive_link",
                            "detail": "sdist link",
                        }
                    )
                elif not (member.isfile() or member.isdir()):
                    findings.append(
                        {
                            "path": name,
                            "kind": "non_regular_archive_member",
                            "detail": "sdist member is not a regular file or directory",
                        }
                    )
                if (
                    CACHE_DIRECTORY_NAME in relative_parts
                    or relative.casefold().endswith((".pyc", ".pyo"))
                ):
                    findings.append(
                        {
                            "path": name,
                            "kind": "cache_artifact",
                            "detail": "generated bytecode",
                        }
                    )
                if any(
                    part == ".env" or part.startswith(".env.")
                    for part in relative_parts
                ) or any(
                    part in {".git", ".venv", ".release-preview"}
                    for part in relative_parts
                ):
                    findings.append(
                        {
                            "path": name,
                            "kind": "private_archive_file",
                            "detail": "private or dotenv content",
                        }
                    )
                if (
                    "tests" in relative_parts
                    or any(part.startswith("test_") for part in relative_parts)
                ):
                    findings.append(
                        {
                            "path": name,
                            "kind": "test_content",
                            "detail": "tests are excluded from release sdist",
                        }
                    )
                benchmark_prefix = (
                    "src/data_audit_toolkit/benchmark_data/"
                )
                if (
                    member.isfile()
                    and relative.startswith(benchmark_prefix)
                ):
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        findings.append(
                            {
                                "path": name,
                                "kind": "invalid_sdist",
                                "detail": "regular member is unreadable",
                            }
                        )
                    else:
                        benchmark_resources[relative] = _sha256(extracted.read())
    except (OSError, tarfile.TarError) as error:
        return [
            {
                "path": sdist.name,
                "kind": "invalid_sdist",
                "detail": type(error).__name__,
            }
        ]

    if len(archive_roots) != 1:
        findings.append(
            {
                "path": sdist.name,
                "kind": "invalid_sdist_root",
                "detail": f"expected one archive root, found {sorted(archive_roots)}",
            }
        )
    mismatch = _benchmark_contract_finding(
        sdist.name,
        expected,
        benchmark_resources,
    )
    if mismatch:
        findings.append(mismatch)
    return findings


def run_process(
    arguments: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(arguments),
            cwd=str(cwd),
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    except (OSError, ValueError) as error:
        return subprocess.CompletedProcess(
            args=list(arguments),
            returncode=127,
            stdout="",
            stderr=f"process setup failed: {type(error).__name__}: {error}",
        )


_run_process = run_process


def scrubbed_python_environment(
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = dict(os.environ if source is None else source)
    for variable in PYTHON_ENVIRONMENT_VARIABLES:
        environment.pop(variable, None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONSAFEPATH"] = "1"
    return environment


def _output_tail(process: subprocess.CompletedProcess[str]) -> str:
    combined = "\n".join(
        part.strip()
        for part in (process.stdout, process.stderr)
        if part.strip()
    )
    return combined[-4000:]


def _record_process_gate(
    gates: dict[str, dict[str, Any]],
    name: str,
    process: subprocess.CompletedProcess[str],
) -> bool:
    if process.returncode == 0:
        gates[name] = {"status": "passed"}
        return True
    gates[name] = {
        "status": "failed",
        "returncode": process.returncode,
        "output_tail": _output_tail(process),
    }
    return False


def _benchmark_is_complete(output: str) -> bool:
    try:
        payload = json.loads(output)
    except (TypeError, ValueError):
        return False
    return payload.get("case_count") == 19 and payload.get("failures") == {}


def is_trusted_validator_executable(
    candidate: Path,
    *,
    python_executable: Path,
) -> bool:
    expected = python_executable.parent / "skills-ref"
    try:
        metadata = candidate.lstat()
        return bool(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and os.access(candidate, os.X_OK)
            and candidate.resolve(strict=True) == expected.resolve(strict=True)
        )
    except OSError:
        return False


def _validator_path() -> Path | None:
    beside_python = Path(sys.executable).with_name("skills-ref")
    if is_trusted_validator_executable(
        beside_python,
        python_executable=Path(sys.executable),
    ):
        return beside_python
    return None


def is_safe_skill_name(name: str) -> bool:
    return bool(
        1 <= len(name) <= 64
        and SKILL_NAME_PATTERN.fullmatch(name)
    )


def _declared_skill_name(root: Path) -> str:
    try:
        lines = (root / "SKILL.md").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError(f"SKILL.md is unreadable: {type(error).__name__}") from error
    delimiter_count = 0
    for line in lines:
        if line == "---":
            delimiter_count += 1
            if delimiter_count == 2:
                break
            continue
        if delimiter_count == 1 and line.startswith("name:"):
            name = line.split(":", 1)[1].strip()
            if is_safe_skill_name(name):
                return name
            raise ValueError("SKILL.md name is not one safe grammar component")
    raise ValueError("SKILL.md does not declare a valid frontmatter name")


def prepare_skill_validation_copy(
    root: Path,
    validation_root: Path,
) -> Path:
    skill_name = _declared_skill_name(root)
    resolved_validation_root = validation_root.resolve(strict=True)
    target_directory = resolved_validation_root / skill_name
    if (
        target_directory.parent != resolved_validation_root
        or not target_directory.is_relative_to(resolved_validation_root)
    ):
        raise ValueError("skill validation target escapes temporary root")
    target_directory.mkdir(mode=0o700)
    source = root / "SKILL.md"
    source_bytes = source.read_bytes()
    copied = target_directory / "SKILL.md"
    copied.write_bytes(source_bytes)
    if copied.read_bytes() != source_bytes:
        raise OSError("SKILL.md validation copy differs from source bytes")
    return copied


def skills_ref_provenance_findings(
    payload: Mapping[str, Any],
) -> list[dict[str, str]]:
    vcs_info = payload.get("vcs_info")
    if not isinstance(vcs_info, Mapping):
        return [
            {
                "path": "skills-ref/direct_url.json",
                "kind": "validator_provenance",
                "detail": "missing PEP 610 VCS metadata",
            }
        ]
    expected_fields = {
        "url": SKILLS_REF_URL,
        "subdirectory": "skills-ref",
    }
    findings: list[dict[str, str]] = []
    for field, expected in expected_fields.items():
        if payload.get(field) != expected:
            findings.append(
                {
                    "path": "skills-ref/direct_url.json",
                    "kind": "validator_provenance",
                    "detail": f"{field} does not match pinned source",
                }
            )
    for field, expected in {
        "vcs": "git",
        "requested_revision": SKILLS_REF_COMMIT,
        "commit_id": SKILLS_REF_COMMIT,
    }.items():
        if vcs_info.get(field) != expected:
            findings.append(
                {
                    "path": "skills-ref/direct_url.json",
                    "kind": "validator_provenance",
                    "detail": f"vcs_info.{field} does not match pinned source",
                }
            )
    return findings


def _installed_skills_ref_provenance_findings() -> list[dict[str, str]]:
    try:
        distribution = importlib.metadata.distribution("skills-ref")
        direct_url_text = distribution.read_text("direct_url.json")
        if direct_url_text is None:
            raise ValueError("direct_url.json is missing")
        payload = json.loads(direct_url_text)
        if not isinstance(payload, Mapping):
            raise ValueError("direct_url.json is not an object")
    except (
        importlib.metadata.PackageNotFoundError,
        OSError,
        UnicodeError,
        ValueError,
    ) as error:
        return [
            {
                "path": "skills-ref/direct_url.json",
                "kind": "validator_provenance",
                "detail": type(error).__name__,
            }
        ]
    return skills_ref_provenance_findings(payload)


def _venv_executables(venv_root: Path) -> tuple[Path, Path]:
    if os.name == "nt":
        return (
            venv_root / "Scripts" / "python.exe",
            venv_root / "Scripts" / "data-audit.exe",
        )
    return (
        venv_root / "bin" / "python",
        venv_root / "bin" / "data-audit",
    )


def remove_generated_artifacts(root: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for name in ("build", "dist"):
        target = root / name
        try:
            metadata = target.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            findings.append(
                {
                    "path": name,
                    "kind": "cleanup_failure",
                    "detail": type(error).__name__,
                }
            )
            continue
        if stat.S_ISLNK(metadata.st_mode):
            findings.append(
                {
                    "path": name,
                    "kind": "cleanup_failure",
                    "detail": "refusing to remove symlink",
                }
            )
            continue
        try:
            if stat.S_ISDIR(metadata.st_mode):
                shutil.rmtree(target)
            else:
                target.unlink()
        except OSError as error:
            findings.append(
                {
                    "path": name,
                    "kind": "cleanup_failure",
                    "detail": type(error).__name__,
                }
            )
    return findings


_remove_generated_artifacts = remove_generated_artifacts


def git_head_matches(root: Path, expected_head: str) -> tuple[bool, str]:
    process = run_process(["git", "rev-parse", "HEAD"], cwd=root)
    actual_head = process.stdout.strip() if process.returncode == 0 else "unknown"
    matches = process.returncode == 0 and actual_head == expected_head
    return (
        matches,
        f"expected {expected_head}; actual {actual_head}",
    )


def _extract_archive_snapshot(archive_path: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700, parents=True)
    resolved_destination = destination.resolve(strict=True)
    with tarfile.open(archive_path, "r:") as archive:
        for member in archive.getmembers():
            if (
                _unsafe_archive_name(member.name)
                or member.issym()
                or member.islnk()
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError(f"unsafe Git archive member: {member.name}")
            target = destination / member.name
            resolved_target = target.resolve(strict=False)
            if not resolved_target.is_relative_to(resolved_destination):
                raise ValueError(f"Git archive member escapes snapshot: {member.name}")
            if member.isdir():
                target.mkdir(mode=member.mode & 0o777, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise OSError(f"Git archive member is unreadable: {member.name}")
            with target.open("wb") as output:
                shutil.copyfileobj(extracted, output)
            target.chmod(member.mode & 0o777)


def create_release_snapshot(
    root: Path,
    commit: str,
    destination: Path,
) -> Path:
    if destination.exists():
        raise FileExistsError(f"snapshot destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="release_archive_",
        dir=destination.parent,
    ) as archive_temporary:
        archive_path = Path(archive_temporary) / "release.tar"
        process = run_process(
            [
                "git",
                "archive",
                "--format=tar",
                "--output",
                str(archive_path),
                commit,
            ],
            cwd=root,
        )
        if process.returncode != 0:
            raise RuntimeError(_output_tail(process) or "git archive failed")
        _extract_archive_snapshot(archive_path, destination)
    return destination


def _project_version(root: Path) -> str:
    try:
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError("pyproject.toml is unreadable") from error
    project_section = re.search(
        r"(?ms)^\[project\]\s*$"
        r"(?P<body>.*?)(?=^\[[^\]]+\]\s*$|\Z)",
        text,
    )
    if project_section is None:
        raise ValueError("pyproject.toml has no project table")
    version_match = re.search(
        r'(?m)^version\s*=\s*"(?P<version>[^"]+)"\s*$',
        project_section.group("body"),
    )
    if version_match is None:
        raise ValueError("pyproject.toml has no static project version")
    return version_match.group("version")


def run_release_checks(
    root: Path,
    forbidden_terms: Sequence[str],
) -> dict[str, Any]:
    root = root.resolve()
    gates: dict[str, dict[str, Any]] = {
        name: {"status": "not_run"}
        for name in GATE_NAMES
    }
    head_process = run_process(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
    )
    commit = (
        head_process.stdout.strip()
        if head_process.returncode == 0
        else "unknown"
    )
    initial_diff = run_process(["git", "diff", "--check"], cwd=root)
    initial_status = run_process(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
    )
    active = bool(
        head_process.returncode == 0
        and initial_diff.returncode == 0
        and initial_status.returncode == 0
        and not initial_status.stdout.strip()
    )
    if active:
        gates["initial_git"] = {
            "status": "passed",
            "commit": commit,
        }
    else:
        gates["initial_git"] = {
            "status": "failed",
            "detail": "release must start from a clean readable Git commit",
            "head": _output_tail(head_process),
            "diff": _output_tail(initial_diff),
            "status_output": _output_tail(initial_status),
        }

    snapshot_workspace: Path | None = None
    snapshot_root: Path | None = None
    snapshot_roots: list[Path] = []
    wheel: Path | None = None
    sdist: Path | None = None
    cleanup_findings: list[dict[str, str]] = []
    current_gate = "snapshot"
    try:
        if active:
            snapshot_workspace = Path(
                tempfile.mkdtemp(prefix="data_audit_release_snapshot_")
            )
            snapshot_root = create_release_snapshot(
                root,
                commit,
                snapshot_workspace / "test-project",
            )
            snapshot_roots.append(snapshot_root)
            gates["snapshot"] = {
                "status": "passed",
                "commit": commit,
            }

        if active and snapshot_root is not None:
            current_gate = "public_hygiene"
            findings = scan_candidate_tree(snapshot_root, forbidden_terms)
            if findings:
                gates["public_hygiene"] = {
                    "status": "failed",
                    "findings": findings,
                }
                active = False
            else:
                gates["public_hygiene"] = {"status": "passed"}

        source_environment = scrubbed_python_environment()
        if snapshot_root is not None:
            source_environment["PYTHONPATH"] = os.pathsep.join(
                (str(snapshot_root), str(snapshot_root / "src"))
            )
        source_environment["PYTHONDONTWRITEBYTECODE"] = "1"

        if active and snapshot_root is not None:
            current_gate = "unit_tests"
            process = _run_process(
                [
                    sys.executable,
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "tests",
                    "-v",
                ],
                cwd=snapshot_root,
                env=source_environment,
            )
            active = _record_process_gate(gates, "unit_tests", process)
        if active and snapshot_root is not None:
            current_gate = "benchmark"
            process = _run_process(
                [
                    sys.executable,
                    str(snapshot_root / "scripts" / "check_benchmark_suite.py"),
                ],
                cwd=snapshot_root,
                env=source_environment,
            )
            if process.returncode == 0 and _benchmark_is_complete(process.stdout):
                gates["benchmark"] = {"status": "passed", "case_count": 19}
            else:
                gates["benchmark"] = {
                    "status": "failed",
                    "returncode": process.returncode,
                    "output_tail": _output_tail(process),
                }
                active = False
        if (
            active
            and snapshot_workspace is not None
            and snapshot_root is not None
        ):
            current_gate = "snapshot"
            snapshot_root = create_release_snapshot(
                root,
                commit,
                snapshot_workspace / "build-project",
            )
            snapshot_roots.append(snapshot_root)
            gates["snapshot"] = {
                "status": "passed",
                "commit": commit,
                "phase_count": 2,
            }
            source_environment = scrubbed_python_environment()
            source_environment["PYTHONPATH"] = os.pathsep.join(
                (str(snapshot_root), str(snapshot_root / "src"))
            )
            source_environment["PYTHONDONTWRITEBYTECODE"] = "1"
        if active and snapshot_root is not None:
            current_gate = "build"
            process = _run_process(
                [sys.executable, "-m", "build"],
                cwd=snapshot_root,
                env=source_environment,
            )
            active = _record_process_gate(gates, "build", process)
            distributions = snapshot_root / "dist"
            wheels = sorted(distributions.glob("*.whl")) if active else []
            sdists = sorted(distributions.glob("*.tar.gz")) if active else []
            if active and len(wheels) == 1 and len(sdists) == 1:
                wheel = wheels[0]
                sdist = sdists[0]
            elif active:
                gates["build"] = {
                    "status": "failed",
                    "detail": (
                        "build must produce exactly one wheel and one source archive"
                    ),
                }
                active = False
        if active and wheel is not None and snapshot_root is not None:
            current_gate = "wheel_contents"
            wheel_findings = inspect_wheel_contents(
                wheel,
                root=snapshot_root,
            )
            if wheel_findings:
                gates["wheel_contents"] = {
                    "status": "failed",
                    "findings": wheel_findings,
                }
                active = False
            else:
                gates["wheel_contents"] = {"status": "passed"}
        if active and sdist is not None and snapshot_root is not None:
            current_gate = "sdist_contents"
            sdist_findings = inspect_sdist_contents(
                sdist,
                root=snapshot_root,
            )
            if sdist_findings:
                gates["sdist_contents"] = {
                    "status": "failed",
                    "findings": sdist_findings,
                }
                active = False
            else:
                gates["sdist_contents"] = {"status": "passed"}
        if active and wheel is not None and sdist is not None and snapshot_root:
            current_gate = "twine"
            process = _run_process(
                [
                    sys.executable,
                    "-m",
                    "twine",
                    "check",
                    str(wheel),
                    str(sdist),
                ],
                cwd=snapshot_root,
                env=source_environment,
            )
            active = _record_process_gate(gates, "twine", process)
        if active and snapshot_root is not None:
            current_gate = "agent_skill"
            validator = _validator_path()
            provenance_findings = _installed_skills_ref_provenance_findings()
            if validator is None or provenance_findings:
                gates["agent_skill"] = {
                    "status": "failed",
                    "detail": (
                        "skills-ref executable or pinned PEP 610 provenance "
                        "is unavailable"
                    ),
                    "findings": provenance_findings,
                }
                active = False
            else:
                with tempfile.TemporaryDirectory(
                    prefix="agent_skill_validation_"
                ) as validation_temp:
                    copied_skill = prepare_skill_validation_copy(
                        snapshot_root,
                        Path(validation_temp),
                    )
                    process = _run_process(
                        [
                            str(validator),
                            "validate",
                            str(copied_skill.parent),
                        ],
                        cwd=snapshot_root,
                        env=scrubbed_python_environment(),
                    )
                    active = _record_process_gate(
                        gates,
                        "agent_skill",
                        process,
                    )
        with tempfile.TemporaryDirectory(
            prefix="data_audit_release_install_"
        ) as temp:
            temp_root = Path(temp)
            venv_root = temp_root / "venv"
            venv_python, data_audit = _venv_executables(venv_root)
            installed_environment = scrubbed_python_environment()
            if active and wheel is not None and snapshot_root is not None:
                current_gate = "wheel_install"
                create_process = _run_process(
                    [sys.executable, "-m", "venv", str(venv_root)],
                    cwd=temp_root,
                    env=installed_environment,
                )
                if create_process.returncode == 0:
                    install_process = _run_process(
                        [
                            str(venv_python),
                            "-m",
                            "pip",
                            "install",
                            "--disable-pip-version-check",
                            "--no-deps",
                            str(wheel),
                        ],
                        cwd=temp_root,
                        env=installed_environment,
                    )
                else:
                    install_process = create_process
                active = _record_process_gate(
                    gates,
                    "wheel_install",
                    install_process,
                )
            if active:
                current_gate = "wheel_version"
                version_process = _run_process(
                    [str(data_audit), "--version"],
                    cwd=temp_root,
                    env=installed_environment,
                )
                expected_version = _project_version(snapshot_root)
                if (
                    version_process.returncode == 0
                    and version_process.stdout.strip()
                    == f"data-audit {expected_version}"
                ):
                    gates["wheel_version"] = {
                        "status": "passed",
                        "version": expected_version,
                    }
                else:
                    gates["wheel_version"] = {
                        "status": "failed",
                        "returncode": version_process.returncode,
                        "output_tail": _output_tail(version_process),
                    }
                    active = False
            if active:
                current_gate = "wheel_benchmark"
                benchmark_process = _run_process(
                    [str(data_audit), "benchmark"],
                    cwd=temp_root,
                    env=installed_environment,
                )
                if (
                    benchmark_process.returncode == 0
                    and _benchmark_is_complete(benchmark_process.stdout)
                ):
                    gates["wheel_benchmark"] = {
                        "status": "passed",
                        "case_count": 19,
                    }
                else:
                    gates["wheel_benchmark"] = {
                        "status": "failed",
                        "returncode": benchmark_process.returncode,
                        "output_tail": _output_tail(benchmark_process),
                    }
                    active = False
            if active and snapshot_root is not None:
                current_gate = "wheel_scan"
                report_path = temp_root / "synthetic-report.json"
                scan_process = _run_process(
                    [
                        str(data_audit),
                        "scan",
                        str(
                            snapshot_root
                            / "examples"
                            / "synthetic-case"
                            / "source_data.csv"
                        ),
                        "--output",
                        str(report_path),
                    ],
                    cwd=temp_root,
                    env=installed_environment,
                )
                try:
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    report = {}
                if (
                    scan_process.returncode == 0
                    and report.get("schema_version") == "data-audit-v1"
                ):
                    gates["wheel_scan"] = {"status": "passed"}
                else:
                    gates["wheel_scan"] = {
                        "status": "failed",
                        "returncode": scan_process.returncode,
                        "output_tail": _output_tail(scan_process),
                    }
                    active = False
    except Exception as error:
        gates[current_gate] = {
            "status": "failed",
            "detail": f"{type(error).__name__}: {error}",
        }
        active = False
    finally:
        for cleanup_root in snapshot_roots:
            cleanup_findings.extend(
                remove_generated_artifacts(cleanup_root)
            )
        if snapshot_workspace is not None:
            try:
                shutil.rmtree(snapshot_workspace)
            except OSError as error:
                cleanup_findings.append(
                    {
                        "path": snapshot_workspace.name,
                        "kind": "cleanup_failure",
                        "detail": type(error).__name__,
                    }
                )
            if cleanup_findings:
                gates["cleanup"] = {
                    "status": "failed",
                    "findings": cleanup_findings,
                }
            else:
                gates["cleanup"] = {"status": "passed"}

    diff_process = run_process(
        ["git", "diff", "--check"],
        cwd=root,
    )
    _record_process_gate(gates, "diff_check", diff_process)
    if commit != "unknown":
        head_matches, head_detail = git_head_matches(root, commit)
        gates["head_unchanged"] = (
            {"status": "passed", "commit": commit}
            if head_matches
            else {"status": "failed", "detail": head_detail}
        )
    else:
        gates["head_unchanged"] = {
            "status": "failed",
            "detail": "initial commit could not be captured",
        }
    status_process = run_process(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
    )
    if status_process.returncode == 0 and not status_process.stdout.strip():
        gates["status_clean"] = {"status": "passed"}
    else:
        gates["status_clean"] = {
            "status": "failed",
            "returncode": status_process.returncode,
            "output_tail": _output_tail(status_process),
        }

    ok = all(gate["status"] == "passed" for gate in gates.values())
    return {
        "commit": commit,
        "ok": ok,
        "status": "passed" if ok else "failed",
        "gates": gates,
    }


def _outer_failure_summary(error: BaseException) -> dict[str, Any]:
    gates = {
        name: {"status": "not_run"}
        for name in GATE_NAMES
    }
    gates["initial_git"] = {
        "status": "failed",
        "detail": f"unexpected setup failure: {type(error).__name__}",
    }
    return {
        "commit": "unknown",
        "ok": False,
        "status": "failed",
        "gates": gates,
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    root: Path = ROOT,
    output: TextIO = sys.stdout,
) -> int:
    try:
        args = build_parser().parse_args(argv)
        summary = run_release_checks(root, args.forbid_term)
    except Exception as error:
        summary = _outer_failure_summary(error)
    print(
        json.dumps(summary, ensure_ascii=False, sort_keys=True),
        file=output,
    )
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
