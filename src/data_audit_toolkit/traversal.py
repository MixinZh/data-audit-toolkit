from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from collections.abc import Collection, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .models import DEFAULT_LIMITS, Inventory, InventoryEntry, ScanLimits

SUPPORTED_SUFFIXES = frozenset(
    {
        ".txt", ".md", ".markdown",
        ".csv", ".tsv", ".xlsx",
        ".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp",
    }
)

_HASH_CHUNK_BYTES = 1024 * 1024


class _InputChangedError(OSError):
    pass


@dataclass(frozen=True)
class _Candidate:
    path: Path
    relative_path: str
    file_stat: os.stat_result | None
    blocked_reason: str | None = None
    directory_chain: tuple[tuple[str, os.stat_result], ...] = ()


def _root_label(path: Path, index: int, total: int) -> str:
    if total == 1 and path.is_dir():
        return ""
    base = path.name or f"input-{index + 1}"
    return f"input-{index + 1}-{base}"


def _absolute_path(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _is_excluded(path: Path, excluded_paths: tuple[Path, ...]) -> bool:
    return any(path == excluded or excluded in path.parents for excluded in excluded_paths)


def _public_path(label: str, relative_path: str) -> str:
    return f"{label}/{relative_path}" if label else relative_path


def _root_public_path(root: Path, label: str, index: int) -> str:
    return label or root.name or f"input-{index + 1}"


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    if first.st_ino and second.st_ino:
        return first.st_dev == second.st_dev and first.st_ino == second.st_ino
    return stat.S_IFMT(first.st_mode) == stat.S_IFMT(second.st_mode)


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_directory(
    path: str | Path,
    expected_stat: os.stat_result,
    *,
    dir_fd: int | None = None,
) -> int:
    try:
        descriptor = os.open(path, _directory_flags(), dir_fd=dir_fd)
    except (TypeError, NotImplementedError) as exc:
        raise OSError("secure directory traversal is unavailable") from exc
    try:
        opened_stat = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened_stat.st_mode)
            or not _same_identity(expected_stat, opened_stat)
        ):
            raise OSError("directory changed during traversal")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _walk_directory(
    descriptor: int,
    directory: Path,
    root: Path,
    label: str,
    excluded_paths: tuple[Path, ...],
    directory_public_path: str,
    directory_stat: os.stat_result,
    directory_chain: tuple[tuple[str, os.stat_result], ...],
) -> Iterator[_Candidate]:
    try:
        with os.scandir(descriptor) as iterator:
            children = sorted(iterator, key=lambda entry: entry.name)
    except (OSError, TypeError, NotImplementedError):
        yield _Candidate(
            directory,
            directory_public_path,
            directory_stat,
            "filesystem_access_failed",
        )
        return
    for child in children:
        path = directory / child.name
        if _is_excluded(path, excluded_paths):
            continue
        try:
            file_stat = child.stat(follow_symlinks=False)
        except OSError:
            relative_path = path.relative_to(root).as_posix()
            yield _Candidate(
                path,
                _public_path(label, relative_path),
                None,
                "filesystem_access_failed",
            )
            continue
        relative_path = path.relative_to(root).as_posix()
        public_path = _public_path(label, relative_path)
        if stat.S_ISDIR(file_stat.st_mode):
            try:
                child_descriptor = _open_directory(
                    child.name,
                    file_stat,
                    dir_fd=descriptor,
                )
            except OSError:
                yield _Candidate(
                    path,
                    public_path,
                    file_stat,
                    "filesystem_access_failed",
                )
                continue
            try:
                yield from _walk_directory(
                    child_descriptor,
                    path,
                    root,
                    label,
                    excluded_paths,
                    public_path,
                    file_stat,
                    directory_chain + ((child.name, file_stat),),
                )
            finally:
                os.close(child_descriptor)
        else:
            yield _Candidate(
                path,
                public_path,
                file_stat,
                directory_chain=directory_chain,
            )


@contextmanager
def _collect_root_candidates(
    root: Path,
    *,
    label: str,
    root_public_path: str,
    excluded_paths: tuple[Path, ...],
) -> Iterator[tuple[list[_Candidate], int | None]]:
    if _is_excluded(root, excluded_paths):
        yield [], None
        return
    parent_descriptor = None
    try:
        if root.parent == root:
            root_stat = os.lstat(root)
            root_open_path: str | Path = root
        else:
            parent_stat = os.lstat(root.parent)
            parent_descriptor = _open_directory(root.parent, parent_stat)
            try:
                root_stat = os.stat(
                    root.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except (TypeError, NotImplementedError) as exc:
                raise OSError("secure file traversal is unavailable") from exc
            root_open_path = root.name
    except OSError:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        yield [
            _Candidate(
                root,
                root_public_path,
                None,
                "filesystem_access_failed",
            )
        ], None
        return
    if not stat.S_ISDIR(root_stat.st_mode):
        candidate = _Candidate(root, root_public_path, root_stat)
        try:
            yield [candidate], parent_descriptor
        finally:
            if parent_descriptor is not None:
                os.close(parent_descriptor)
        return
    try:
        descriptor = _open_directory(
            root_open_path,
            root_stat,
            dir_fd=parent_descriptor,
        )
    except OSError:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        yield [
            _Candidate(
                root,
                root_public_path,
                root_stat,
                "filesystem_access_failed",
            )
        ], None
        return
    if parent_descriptor is not None:
        os.close(parent_descriptor)
    try:
        candidates = sorted(
            _walk_directory(
                descriptor,
                root,
                root,
                label,
                excluded_paths,
                root_public_path,
                root_stat,
                (),
            ),
            key=lambda item: item.relative_path,
        )
        yield candidates, descriptor
    finally:
        os.close(descriptor)


def _open_regular_file(
    path: str | Path,
    expected_stat: os.stat_result | None = None,
    *,
    dir_fd: int | None = None,
) -> int:
    try:
        if dir_fd is None:
            current_stat = os.lstat(path)
        else:
            current_stat = os.stat(
                path,
                dir_fd=dir_fd,
                follow_symlinks=False,
            )
    except (TypeError, NotImplementedError) as exc:
        raise OSError("secure file traversal is unavailable") from exc
    if not stat.S_ISREG(current_stat.st_mode):
        raise _InputChangedError("input is no longer a regular file")
    if expected_stat is not None and not _same_identity(expected_stat, current_stat):
        raise _InputChangedError("input identity changed")
    try:
        descriptor = os.open(path, _file_flags(), dir_fd=dir_fd)
    except (TypeError, NotImplementedError) as exc:
        raise OSError("secure file traversal is unavailable") from exc
    try:
        opened_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_stat.st_mode)
            or not _same_identity(current_stat, opened_stat)
            or (
                expected_stat is not None
                and not _same_identity(expected_stat, opened_stat)
            )
        ):
            raise _InputChangedError("input identity changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_regular_from_root(
    root_descriptor: int,
    candidate: _Candidate,
) -> int:
    if candidate.file_stat is None:
        raise OSError("input metadata unavailable")
    directory_descriptor = os.dup(root_descriptor)
    try:
        for component, expected_stat in candidate.directory_chain:
            child_descriptor = _open_directory(
                component,
                expected_stat,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = child_descriptor
        return _open_regular_file(
            candidate.path.name,
            candidate.file_stat,
            dir_fd=directory_descriptor,
        )
    finally:
        os.close(directory_descriptor)


def _hash_descriptor(
    descriptor: int,
    expected_size: int,
    output: BinaryIO | None = None,
) -> str:
    opened_stat = os.fstat(descriptor)
    if opened_stat.st_size != expected_size:
        raise _InputChangedError("input size changed")
    digest = hashlib.sha256()
    remaining = expected_size
    with os.fdopen(descriptor, "rb", closefd=False) as handle:
        while remaining:
            requested = min(_HASH_CHUNK_BYTES, remaining)
            chunk = handle.read(requested)
            if not chunk or len(chunk) > requested:
                raise _InputChangedError("input size changed")
            digest.update(chunk)
            if output is not None:
                written = output.write(chunk)
                if written != len(chunk):
                    raise OSError("snapshot write was incomplete")
            remaining -= len(chunk)
        if handle.read(1):
            raise _InputChangedError("input grew during inventory")
    final_stat = os.fstat(descriptor)
    if (
        opened_stat.st_size != final_stat.st_size
        or opened_stat.st_mtime_ns != final_stat.st_mtime_ns
    ):
        raise _InputChangedError("input changed during inventory")
    return digest.hexdigest()


def _sha256_descriptor(
    descriptor: int,
    expected_stat: os.stat_result,
    destination: Path | None = None,
) -> str:
    if destination is None:
        return _hash_descriptor(descriptor, expected_stat.st_size)
    with destination.open("xb") as output:
        digest = _hash_descriptor(
            descriptor,
            expected_stat.st_size,
            output,
        )
    destination.chmod(stat.S_IRUSR)
    return digest


def _collect_inputs(
    inputs: Sequence[str | Path],
    *,
    limits: ScanLimits,
    excluded_paths: Collection[Path],
    supported_suffixes: Collection[str],
    snapshot_root: Path | None,
) -> tuple[Inventory, dict[str, Path]]:
    roots = tuple(_absolute_path(item) for item in inputs)
    if not roots:
        raise ValueError("at least one input path is required")
    exclusions = tuple(_absolute_path(item) for item in excluded_paths)
    supported = frozenset(suffix.casefold() for suffix in supported_suffixes)
    root_specs: list[tuple[str, Path, str]] = []
    for index, root in enumerate(roots):
        label = _root_label(root, index, len(roots))
        root_specs.append(
            (
                _root_public_path(root, label, index),
                root,
                label,
            )
        )
    root_specs.sort(key=lambda item: item[0])

    entries: list[InventoryEntry] = []
    seen_regular_files: set[tuple[int, int] | tuple[str, str]] = set()
    regular_file_count = 0
    total_bytes = 0
    snapshots: dict[str, Path] = {}
    for root_public_path, root, label in root_specs:
        with _collect_root_candidates(
            root,
            label=label,
            root_public_path=root_public_path,
            excluded_paths=exclusions,
        ) as (candidates, root_descriptor):
            for candidate in candidates:
                path = candidate.path
                relative_path = candidate.relative_path
                file_stat = candidate.file_stat
                mode = file_stat.st_mode if file_stat is not None else 0
                size = file_stat.st_size if file_stat is not None else 0
                if stat.S_ISREG(mode):
                    identity: tuple[int, int] | tuple[str, str]
                    if file_stat is not None and file_stat.st_ino:
                        identity = (file_stat.st_dev, file_stat.st_ino)
                    else:
                        identity = ("path", os.path.normcase(str(path)))
                    if identity in seen_regular_files:
                        continue
                    seen_regular_files.add(identity)

                if candidate.blocked_reason is not None:
                    status, reason = "blocked", candidate.blocked_reason
                elif stat.S_ISLNK(mode):
                    status, reason = "blocked", "symlink_not_followed"
                elif not stat.S_ISREG(mode):
                    status, reason = "blocked", "special_file_blocked"
                elif size > limits.max_file_bytes:
                    status, reason = "blocked", "max_file_bytes_exceeded"
                elif regular_file_count >= limits.max_files:
                    status, reason = "blocked", "max_files_exceeded"
                elif total_bytes + size > limits.max_total_bytes:
                    status, reason = "blocked", "max_total_bytes_exceeded"
                elif path.suffix.casefold() not in supported:
                    status, reason = "unsupported", "unsupported_file_type"
                else:
                    status, reason = "eligible", None

                sha256 = None
                if status in {"eligible", "unsupported"}:
                    snapshot_path = None
                    source_descriptor = None
                    source_root_descriptor = root_descriptor
                    close_source = False
                    try:
                        if file_stat is None:
                            raise OSError("input metadata unavailable")
                        if source_root_descriptor is None:
                            raise OSError("verified input root unavailable")
                        source_descriptor = _open_regular_from_root(
                            source_root_descriptor,
                            candidate,
                        )
                        close_source = True
                        if status == "eligible" and snapshot_root is not None:
                            snapshot_dir = snapshot_root / f"{len(entries):08d}"
                            snapshot_dir.mkdir()
                            snapshot_path = snapshot_dir / path.name
                        sha256 = _sha256_descriptor(
                            source_descriptor,
                            file_stat,
                            snapshot_path,
                        )
                    except _InputChangedError:
                        status, reason = "blocked", "file_changed_during_inventory"
                    except OSError:
                        status, reason = "blocked", "file_read_failed"
                    else:
                        regular_file_count += 1
                        total_bytes += size
                        if snapshot_path is not None:
                            snapshots[relative_path] = snapshot_path
                    finally:
                        if close_source and source_descriptor is not None:
                            os.close(source_descriptor)
                entries.append(
                    InventoryEntry(
                        absolute_path=path,
                        relative_path=relative_path,
                        size_bytes=size,
                        sha256=sha256,
                        status=status,
                        reason=reason,
                    )
                )
    return Inventory(entries=tuple(entries), input_roots=roots), snapshots


def collect_inputs(
    inputs: Sequence[str | Path],
    *,
    limits: ScanLimits = DEFAULT_LIMITS,
    excluded_paths: Collection[Path] = (),
    supported_suffixes: Collection[str] = SUPPORTED_SUFFIXES,
) -> Inventory:
    inventory, _ = _collect_inputs(
        inputs,
        limits=limits,
        excluded_paths=excluded_paths,
        supported_suffixes=supported_suffixes,
        snapshot_root=None,
    )
    return inventory


@contextmanager
def _collect_inputs_with_snapshots(
    inputs: Sequence[str | Path],
    *,
    limits: ScanLimits = DEFAULT_LIMITS,
    excluded_paths: Collection[Path] = (),
    supported_suffixes: Collection[str] = SUPPORTED_SUFFIXES,
) -> Iterator[tuple[Inventory, dict[str, Path]]]:
    with tempfile.TemporaryDirectory(prefix="data_audit_scan_") as temp:
        yield _collect_inputs(
            inputs,
            limits=limits,
            excluded_paths=excluded_paths,
            supported_suffixes=supported_suffixes,
            snapshot_root=Path(temp),
        )
