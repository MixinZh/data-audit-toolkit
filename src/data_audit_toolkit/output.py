from __future__ import annotations

import json
import os
import secrets
import stat
import unicodedata
from collections.abc import Collection, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FileIdentity = tuple[int, int]
ParentLeafIdentity = tuple[FileIdentity, str]
NormalizedPathKey = tuple[str, ...]


class OutputPathError(ValueError):
    pass


class OutputInputConflictError(OutputPathError):
    pass


class OutputExistsError(FileExistsError):
    pass


class OutputWriteError(OSError):
    pass


@dataclass(frozen=True)
class _PreparedOutputTarget:
    lexical_path: Path
    parent_path: Path
    name: str
    parent_descriptor: int
    parent_identity: FileIdentity

    @property
    def path(self) -> Path:
        return self.parent_path / self.name

    @property
    def excluded_paths(self) -> tuple[Path, ...]:
        return _filesystem_equivalent_output_paths(self)


def _identity(file_stat: os.stat_result) -> FileIdentity:
    return (file_stat.st_dev, file_stat.st_ino)


def existing_regular_file_identities(
    paths: Collection[str | Path],
) -> frozenset[FileIdentity]:
    identities: set[FileIdentity] = set()
    for path in paths:
        try:
            file_stat = os.stat(Path(path).expanduser(), follow_symlinks=True)
        except OSError:
            continue
        if stat.S_ISREG(file_stat.st_mode):
            identities.add(_identity(file_stat))
    return frozenset(identities)


@dataclass(frozen=True)
class _ProtectedInputSnapshot(Collection[Path]):
    aliases: tuple[Path, ...]
    normalized_path_keys: frozenset[NormalizedPathKey]
    parent_leaf_identities: frozenset[ParentLeafIdentity]
    verified_output_aliases: frozenset[Path]

    def __contains__(self, item: object) -> bool:
        return item in self.aliases

    def __iter__(self) -> Iterator[Path]:
        return iter(self.aliases)

    def __len__(self) -> int:
        return len(self.aliases)


def _normalized_path_component(component: str) -> str:
    normalized = unicodedata.normalize("NFC", component)
    return unicodedata.normalize("NFC", normalized.casefold())


def _normalized_path_key(path: Path) -> NormalizedPathKey:
    """Return the conservative, filesystem-independent explicit-path key.

    Case- or NFC-only spelling differences are deliberately conflicts even on
    sensitive filesystems. Component keys avoid relying on raceable filesystem
    capability observations while preserving path boundaries.
    """
    absolute_path = Path(os.path.abspath(os.fspath(path)))
    return tuple(
        _normalized_path_component(component)
        for component in absolute_path.parts
    )


def _normalized_leaf(name: str) -> str:
    return _normalized_path_component(name)


def _safe_parent_alias(parent: Path) -> Path | None:
    try:
        return parent.resolve(strict=False)
    except OSError:
        return None


def _raw_absolute_path(path: str | Path) -> Path:
    requested_path = Path(path).expanduser()
    if requested_path.is_absolute():
        return requested_path
    return Path.cwd() / requested_path


def protected_input_paths(
    paths: Collection[str | Path],
) -> tuple[Path, ...]:
    if isinstance(paths, _ProtectedInputSnapshot):
        return paths.aliases
    aliases: set[Path] = set()
    for path in paths:
        raw_absolute_path = _raw_absolute_path(path)
        lexical_path = Path(
            os.path.abspath(os.fspath(raw_absolute_path))
        )
        aliases.add(lexical_path)
        # Resolve before lexical ``..`` collapse so a followed parent symlink
        # contributes the safe alias even when deeper components are missing.
        parent_alias = _safe_parent_alias(raw_absolute_path.parent)
        if parent_alias is not None:
            aliases.add(parent_alias / raw_absolute_path.name)
    return tuple(sorted(aliases, key=os.fspath))


def _protected_input_snapshot(
    paths: Collection[str | Path],
    output_path: str | Path | None = None,
) -> _ProtectedInputSnapshot:
    if isinstance(paths, _ProtectedInputSnapshot):
        return paths
    aliases = protected_input_paths(paths)
    parent_leaf_identities: set[ParentLeafIdentity] = set()
    for protected_path in aliases:
        try:
            parent_stat = os.stat(
                protected_path.parent,
                follow_symlinks=True,
            )
        except OSError:
            continue
        if stat.S_ISDIR(parent_stat.st_mode):
            parent_leaf_identities.add(
                (
                    _identity(parent_stat),
                    _normalized_leaf(protected_path.name),
                )
            )
    verified_output_aliases: set[Path] = set()
    if output_path is not None:
        for output_alias in protected_input_paths((output_path,)):
            try:
                output_parent_stat = os.stat(
                    output_alias.parent,
                    follow_symlinks=True,
                )
            except OSError:
                continue
            if (
                stat.S_ISDIR(output_parent_stat.st_mode)
                and (
                    _identity(output_parent_stat),
                    _normalized_leaf(output_alias.name),
                )
                in parent_leaf_identities
            ):
                verified_output_aliases.add(output_alias)
    return _ProtectedInputSnapshot(
        aliases=aliases,
        normalized_path_keys=frozenset(
            _normalized_path_key(path) for path in aliases
        ),
        parent_leaf_identities=frozenset(parent_leaf_identities),
        verified_output_aliases=frozenset(verified_output_aliases),
    )


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


@contextmanager
def prepare_output_target(
    output_path: str | Path,
) -> Iterator[_PreparedOutputTarget]:
    raw_absolute_path = _raw_absolute_path(output_path)
    lexical_path = Path(os.path.abspath(os.fspath(raw_absolute_path)))
    if not lexical_path.name:
        raise OutputPathError("output path is invalid")
    try:
        parent_path = _safe_parent_alias(raw_absolute_path.parent)
        if parent_path is None:
            raise OutputWriteError("could not prepare report output")
        parent_path.mkdir(parents=True, exist_ok=True)
        parent_path = parent_path.resolve(strict=True)
        expected_parent = os.stat(parent_path, follow_symlinks=False)
        if not stat.S_ISDIR(expected_parent.st_mode):
            raise OutputPathError("output parent is not a directory")
        parent_descriptor = os.open(parent_path, _directory_flags())
    except (OutputPathError, OutputWriteError):
        raise
    except OSError as exc:
        raise OutputWriteError("could not prepare report output") from exc
    try:
        opened_parent = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(opened_parent.st_mode)
            or _identity(opened_parent) != _identity(expected_parent)
        ):
            raise OutputWriteError("could not prepare report output")
        parent_identity = _identity(opened_parent)
        target = _PreparedOutputTarget(
            lexical_path=lexical_path,
            parent_path=parent_path,
            name=raw_absolute_path.name,
            parent_descriptor=parent_descriptor,
            parent_identity=parent_identity,
        )
        yield target
    finally:
        os.close(parent_descriptor)


def _stat_output_leaf(
    target: _PreparedOutputTarget,
) -> os.stat_result | None:
    try:
        return os.stat(
            target.name,
            dir_fd=target.parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except (TypeError, NotImplementedError) as exc:
        raise OutputWriteError("safe report output is unavailable") from exc
    except OSError as exc:
        raise OutputWriteError("could not inspect report output") from exc


def _filesystem_equivalent_output_paths(
    target: _PreparedOutputTarget,
) -> tuple[Path, ...]:
    aliases = {target.lexical_path, target.path}
    file_stat = _stat_output_leaf(target)
    if file_stat is None or not stat.S_ISREG(file_stat.st_mode):
        return tuple(sorted(aliases, key=os.fspath))
    target_identity = _identity(file_stat)
    try:
        with os.scandir(target.parent_descriptor) as entries:
            for entry in entries:
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if (
                    stat.S_ISREG(entry_stat.st_mode)
                    and _identity(entry_stat) == target_identity
                ):
                    aliases.add(target.parent_path / entry.name)
                    aliases.add(target.lexical_path.parent / entry.name)
    except (TypeError, NotImplementedError) as exc:
        raise OutputWriteError("safe report output is unavailable") from exc
    except OSError as exc:
        raise OutputWriteError("could not inspect report output") from exc
    return tuple(sorted(aliases, key=os.fspath))


def _target_matches_protected_path(
    target: _PreparedOutputTarget,
    paths: Collection[str | Path],
) -> bool:
    protected = _protected_input_snapshot(paths)
    target_leaf = _normalized_leaf(target.name)
    target_aliases = (target.lexical_path, target.path)
    if any(
        _normalized_path_key(target_path) in protected.normalized_path_keys
        for target_path in target_aliases
    ):
        return True
    if (
        target.parent_identity,
        target_leaf,
    ) in protected.parent_leaf_identities:
        return True
    return (
        target.lexical_path in protected.verified_output_aliases
        or target.path in protected.verified_output_aliases
    )


def validate_output_target(
    target: _PreparedOutputTarget,
    *,
    overwrite: bool,
    protected_identities: Collection[FileIdentity] = (),
    protected_paths: Collection[str | Path] = (),
) -> None:
    if _target_matches_protected_path(target, protected_paths):
        raise OutputInputConflictError("output path is an explicit input")
    file_stat = _stat_output_leaf(target)
    if file_stat is None:
        return
    if stat.S_ISLNK(file_stat.st_mode):
        raise OutputPathError("output path must not be a symlink")
    if not stat.S_ISREG(file_stat.st_mode):
        raise OutputPathError("output path must be a regular file")
    live_identities = existing_regular_file_identities(protected_paths)
    if _identity(file_stat) in set(protected_identities) | set(live_identities):
        raise OutputInputConflictError("output path is an explicit input")
    if not overwrite:
        raise OutputExistsError(
            "output already exists; use --overwrite to replace it"
        )


def _create_temporary_output(target: _PreparedOutputTarget) -> tuple[int, str]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for _ in range(100):
        name = f".data-audit-{secrets.token_hex(16)}.tmp"
        try:
            descriptor = os.open(
                name,
                flags,
                0o600,
                dir_fd=target.parent_descriptor,
            )
        except FileExistsError:
            continue
        except (TypeError, NotImplementedError) as exc:
            raise OutputWriteError("safe report output is unavailable") from exc
        except OSError as exc:
            raise OutputWriteError("could not create report output") from exc
        return descriptor, name
    raise OutputWriteError("could not create report output")


def _remove_temporary_output(
    target: _PreparedOutputTarget,
    temporary_name: str,
) -> bool:
    try:
        os.unlink(temporary_name, dir_fd=target.parent_descriptor)
    except FileNotFoundError:
        return False
    return True


def _sync_output_directory(target: _PreparedOutputTarget) -> None:
    try:
        os.fsync(target.parent_descriptor)
    except OSError as exc:
        raise OutputWriteError("could not synchronize report output") from exc


def _cleanup_temporary_output(
    target: _PreparedOutputTarget,
    temporary_name: str,
) -> None:
    try:
        removed = _remove_temporary_output(target, temporary_name)
    except OSError as exc:
        raise OutputWriteError("could not clean up report output") from exc
    if removed:
        _sync_output_directory(target)


def _published_target_matches(
    target: _PreparedOutputTarget,
    published_identity: FileIdentity,
) -> bool:
    file_stat = _stat_output_leaf(target)
    return (
        file_stat is not None
        and stat.S_ISREG(file_stat.st_mode)
        and _identity(file_stat) == published_identity
    )


def write_report_atomic_to_target(
    report: Mapping[str, Any],
    target: _PreparedOutputTarget,
    *,
    overwrite: bool,
    protected_identities: Collection[FileIdentity] = (),
    protected_paths: Collection[str | Path] = (),
) -> Path:
    validate_output_target(
        target,
        overwrite=overwrite,
        protected_identities=protected_identities,
        protected_paths=protected_paths,
    )
    descriptor, temporary_name = _create_temporary_output(target)
    temporary_present = True
    try:
        try:
            with os.fdopen(descriptor, mode="w", encoding="utf-8") as handle:
                json.dump(
                    report,
                    handle,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                    allow_nan=False,
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
                temporary_identity = _identity(os.fstat(handle.fileno()))
        except OSError as exc:
            raise OutputWriteError("could not write report output") from exc

        if overwrite:
            validate_output_target(
                target,
                overwrite=True,
                protected_identities=protected_identities,
                protected_paths=protected_paths,
            )
            try:
                os.replace(
                    temporary_name,
                    target.name,
                    src_dir_fd=target.parent_descriptor,
                    dst_dir_fd=target.parent_descriptor,
                )
            except (TypeError, NotImplementedError) as exc:
                raise OutputWriteError("safe report output is unavailable") from exc
            except OSError as exc:
                raise OutputWriteError("could not replace report output") from exc
            temporary_present = False
            _sync_output_directory(target)
        else:
            try:
                os.link(
                    temporary_name,
                    target.name,
                    src_dir_fd=target.parent_descriptor,
                    dst_dir_fd=target.parent_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise OutputExistsError(
                    "output already exists; use --overwrite to replace it"
                ) from exc
            except (TypeError, NotImplementedError) as exc:
                raise OutputWriteError("safe report output is unavailable") from exc
            except OSError as exc:
                raise OutputWriteError("could not publish report output") from exc
            try:
                _sync_output_directory(target)
            except OSError as exc:
                raise OutputWriteError(
                    "could not finalize report output"
                ) from exc
            try:
                _remove_temporary_output(target, temporary_name)
            except OSError as exc:
                if _published_target_matches(target, temporary_identity):
                    temporary_present = False
                    return target.path
                raise OutputWriteError(
                    "could not finalize report output"
                ) from exc
            temporary_present = False
            _sync_output_directory(target)
        return target.path
    finally:
        if temporary_present:
            _cleanup_temporary_output(target, temporary_name)


def write_report_atomic(
    report: Mapping[str, Any],
    output_path: str | Path,
    *,
    overwrite: bool = False,
) -> Path:
    with prepare_output_target(output_path) as target:
        return write_report_atomic_to_target(
            report,
            target,
            overwrite=overwrite,
        )
