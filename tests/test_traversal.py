from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from data_audit_toolkit import traversal
from data_audit_toolkit.models import ScanLimits
from data_audit_toolkit.traversal import collect_inputs


class TraversalTests(unittest.TestCase):
    def test_inode_zero_filesystem_uses_safe_lexical_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "values.csv"
            path.write_text("value\n1\n", encoding="utf-8")
            real_lstat = os.lstat
            real_fstat = os.fstat

            def inode_zero(file_stat: os.stat_result) -> SimpleNamespace:
                return SimpleNamespace(
                    st_mode=file_stat.st_mode,
                    st_ino=0,
                    st_dev=file_stat.st_dev,
                    st_size=file_stat.st_size,
                    st_mtime_ns=file_stat.st_mtime_ns,
                )

            with (
                mock.patch(
                    "data_audit_toolkit.traversal.os.lstat",
                    side_effect=lambda candidate: inode_zero(real_lstat(candidate)),
                ),
                mock.patch(
                    "data_audit_toolkit.traversal.os.fstat",
                    side_effect=lambda descriptor: inode_zero(real_fstat(descriptor)),
                ),
            ):
                inventory = collect_inputs([root])
        entry = inventory.entries[0]
        self.assertEqual("eligible", entry.status)
        self.assertEqual(
            "1a80986111952a11d02e84dbed98ae00f279469aad0615d17fa81911f8a6b428",
            entry.sha256,
        )

    def test_single_directory_uses_relative_paths_and_hashes_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            nested = root / "nested"
            nested.mkdir()
            (nested / "VALUES.CSV").write_text("value\n1\n", encoding="utf-8")
            inventory = collect_inputs([root])
        entry = inventory.entries[0]
        self.assertEqual("nested/VALUES.CSV", entry.relative_path)
        self.assertEqual("eligible", entry.status)
        self.assertEqual(
            "1a80986111952a11d02e84dbed98ae00f279469aad0615d17fa81911f8a6b428",
            entry.sha256,
        )

    def test_multiple_roots_use_deterministic_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            first = parent / "alpha"
            second = parent / "beta"
            first.mkdir()
            second.mkdir()
            (first / "a.csv").write_text("value\n1\n", encoding="utf-8")
            (second / "b.csv").write_text("value\n2\n", encoding="utf-8")
            inventory = collect_inputs([first, second])
        self.assertEqual(
            ["input-1-alpha/a.csv", "input-2-beta/b.csv"],
            [entry.relative_path for entry in inventory.entries],
        )

    def test_symlink_is_blocked_without_reading_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            root = Path(temp)
            secret = Path(outside) / "outside.csv"
            secret.write_text("value\n42\n", encoding="utf-8")
            (root / "linked.csv").symlink_to(secret)
            inventory = collect_inputs([root])
        entry = inventory.entries[0]
        self.assertEqual("blocked", entry.status)
        self.assertEqual("symlink_not_followed", entry.reason)
        self.assertIsNone(entry.sha256)

    def test_file_limit_blocks_entries_after_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for index in range(3):
                (root / f"{index}.csv").write_text("value\n1\n", encoding="utf-8")
            inventory = collect_inputs([root], limits=ScanLimits(max_files=2))
        self.assertEqual(3, len(inventory.entries))
        self.assertEqual(1, sum(entry.reason == "max_files_exceeded" for entry in inventory.entries))

    def test_unsupported_file_is_hashed_and_counts_toward_file_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.pdf").write_bytes(b"%PDF")
            (root / "b.csv").write_text("value\n1\n", encoding="utf-8")
            inventory = collect_inputs([root], limits=ScanLimits(max_files=1))
        first, second = inventory.entries
        self.assertEqual("unsupported", first.status)
        self.assertEqual(64, len(first.sha256 or ""))
        self.assertEqual("blocked", second.status)
        self.assertEqual("max_files_exceeded", second.reason)
        self.assertIsNone(second.sha256)

    def test_file_and_total_byte_limits_block_without_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.csv").write_bytes(b"1234")
            (root / "b.csv").write_bytes(b"5678")
            (root / "large.csv").write_bytes(b"1234567")
            inventory = collect_inputs(
                [root],
                limits=ScanLimits(max_file_bytes=6, max_total_bytes=6),
            )
        entries = {entry.relative_path: entry for entry in inventory.entries}
        self.assertEqual("eligible", entries["a.csv"].status)
        self.assertEqual("max_total_bytes_exceeded", entries["b.csv"].reason)
        self.assertEqual("max_file_bytes_exceeded", entries["large.csv"].reason)
        self.assertIsNone(entries["b.csv"].sha256)
        self.assertIsNone(entries["large.csv"].sha256)

    def test_direct_file_size_limit_is_decided_before_content_open(self) -> None:
        open_calls = 0
        hash_calls = 0
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "large.csv"
            path.write_bytes(b"1234")
            real_hash_descriptor = traversal._hash_descriptor

            def reject_open(*args, **kwargs):
                nonlocal open_calls
                open_calls += 1
                raise OSError("limit-blocked content must not be opened")

            def observe_hash(*args, **kwargs):
                nonlocal hash_calls
                hash_calls += 1
                return real_hash_descriptor(*args, **kwargs)

            with (
                mock.patch(
                    "data_audit_toolkit.traversal._open_regular_file",
                    side_effect=reject_open,
                ),
                mock.patch(
                    "data_audit_toolkit.traversal._hash_descriptor",
                    side_effect=observe_hash,
                ),
            ):
                inventory = collect_inputs(
                    [path],
                    limits=ScanLimits(
                        max_file_bytes=3,
                        max_files=0,
                        max_total_bytes=0,
                    ),
                )
        entry = inventory.entries[0]
        self.assertEqual("max_file_bytes_exceeded", entry.reason)
        self.assertIsNone(entry.sha256)
        self.assertEqual(0, open_calls)
        self.assertEqual(0, hash_calls)

    def test_direct_file_count_limit_is_decided_before_content_open(self) -> None:
        opened_names: list[str] = []
        hash_calls = 0
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "a.csv"
            blocked = root / "b.csv"
            first.write_bytes(b"1234")
            blocked.write_bytes(b"5678")
            real_open_regular_file = traversal._open_regular_file
            real_hash_descriptor = traversal._hash_descriptor

            def reject_blocked(path, expected_stat=None, *, dir_fd=None):
                opened_names.append(Path(path).name)
                if Path(path).name == blocked.name:
                    raise OSError("limit-blocked content must not be opened")
                return real_open_regular_file(
                    path,
                    expected_stat,
                    dir_fd=dir_fd,
                )

            def observe_hash(*args, **kwargs):
                nonlocal hash_calls
                hash_calls += 1
                return real_hash_descriptor(*args, **kwargs)

            with (
                mock.patch(
                    "data_audit_toolkit.traversal._open_regular_file",
                    side_effect=reject_blocked,
                ),
                mock.patch(
                    "data_audit_toolkit.traversal._hash_descriptor",
                    side_effect=observe_hash,
                ),
            ):
                inventory = collect_inputs(
                    [first, blocked],
                    limits=ScanLimits(
                        max_files=1,
                        max_total_bytes=4,
                    ),
                )
        entries = {entry.absolute_path.name: entry for entry in inventory.entries}
        self.assertEqual("eligible", entries[first.name].status)
        self.assertEqual("max_files_exceeded", entries[blocked.name].reason)
        self.assertIsNone(entries[blocked.name].sha256)
        self.assertEqual([first.name], opened_names)
        self.assertEqual(1, hash_calls)

    def test_direct_file_total_limit_is_decided_before_content_open(self) -> None:
        opened_names: list[str] = []
        hash_calls = 0
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "a.csv"
            blocked = root / "b.csv"
            first.write_bytes(b"1234")
            blocked.write_bytes(b"5678")
            real_open_regular_file = traversal._open_regular_file
            real_hash_descriptor = traversal._hash_descriptor

            def reject_blocked(path, expected_stat=None, *, dir_fd=None):
                opened_names.append(Path(path).name)
                if Path(path).name == blocked.name:
                    raise OSError("limit-blocked content must not be opened")
                return real_open_regular_file(
                    path,
                    expected_stat,
                    dir_fd=dir_fd,
                )

            def observe_hash(*args, **kwargs):
                nonlocal hash_calls
                hash_calls += 1
                return real_hash_descriptor(*args, **kwargs)

            with (
                mock.patch(
                    "data_audit_toolkit.traversal._open_regular_file",
                    side_effect=reject_blocked,
                ),
                mock.patch(
                    "data_audit_toolkit.traversal._hash_descriptor",
                    side_effect=observe_hash,
                ),
            ):
                inventory = collect_inputs(
                    [first, blocked],
                    limits=ScanLimits(max_total_bytes=6),
                )
        entries = {entry.absolute_path.name: entry for entry in inventory.entries}
        self.assertEqual("eligible", entries[first.name].status)
        self.assertEqual("max_total_bytes_exceeded", entries[blocked.name].reason)
        self.assertIsNone(entries[blocked.name].sha256)
        self.assertEqual([first.name], opened_names)
        self.assertEqual(1, hash_calls)

    def test_repeated_resolved_regular_file_is_inventoried_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "value.csv").write_text("value\n1\n", encoding="utf-8")
            inventory = collect_inputs([root, root])
        self.assertEqual(1, len(inventory.entries))
        self.assertEqual(
            f"input-1-{root.name}/value.csv",
            inventory.entries[0].relative_path,
        )

    def test_excluded_path_is_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            included = root / "included.csv"
            excluded = root / "excluded.csv"
            included.write_text("value\n1\n", encoding="utf-8")
            excluded.write_text("value\n2\n", encoding="utf-8")
            inventory = collect_inputs([root], excluded_paths=[excluded])
        self.assertEqual(["included.csv"], [entry.relative_path for entry in inventory.entries])

    def test_directory_swap_cannot_expose_outside_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            root = Path(temp)
            nested = root / "nested"
            moved = root / "moved"
            nested.mkdir()
            secret = Path(outside) / "outside.csv"
            secret.write_text("value\n42\n", encoding="utf-8")
            real_relative_to = Path.relative_to
            swapped = False

            def swap_after_child_stat(path: Path, *other: Path) -> Path:
                nonlocal swapped
                relative = real_relative_to(path, *other)
                if path == nested and not swapped:
                    nested.rename(moved)
                    nested.symlink_to(Path(outside), target_is_directory=True)
                    swapped = True
                return relative

            with mock.patch.object(Path, "relative_to", new=swap_after_child_stat):
                inventory = collect_inputs([root])
        self.assertTrue(swapped)
        self.assertNotIn(
            "nested/outside.csv",
            [entry.relative_path for entry in inventory.entries],
        )
        blocked = {entry.relative_path: entry for entry in inventory.entries}
        self.assertEqual("blocked", blocked["nested"].status)
        self.assertEqual("filesystem_access_failed", blocked["nested"].reason)

    def test_growing_file_is_rejected_after_one_bounded_probe(self) -> None:
        read_sizes: list[int] = []

        class GrowingReader:
            def __enter__(self) -> GrowingReader:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self, size: int) -> bytes:
                read_sizes.append(size)
                if len(read_sizes) == 1:
                    return b"1234"
                if len(read_sizes) == 2:
                    return b"x"
                raise AssertionError("inventory read continued after growth was observable")

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "growing.csv"
            path.write_bytes(b"1234")
            with mock.patch(
                "data_audit_toolkit.traversal.os.fdopen",
                return_value=GrowingReader(),
            ):
                inventory = collect_inputs([path])
        entry = inventory.entries[0]
        self.assertEqual("blocked", entry.status)
        self.assertEqual("file_changed_during_inventory", entry.reason)
        self.assertIsNone(entry.sha256)
        self.assertEqual([4, 1], read_sizes)

    def test_missing_root_is_reported_as_sanitized_blocked_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / "missing.csv"
            try:
                inventory = collect_inputs([missing])
            except OSError as exc:
                self.fail(f"missing root escaped collection: {type(exc).__name__}")
        entry = inventory.entries[0]
        self.assertEqual("input-1-missing.csv", entry.relative_path)
        self.assertEqual("blocked", entry.status)
        self.assertEqual("filesystem_access_failed", entry.reason)
        self.assertEqual(0, entry.size_bytes)
        self.assertIsNone(entry.sha256)

    def test_directory_access_error_is_reported_without_exception_text(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with mock.patch(
                "data_audit_toolkit.traversal.os.scandir",
                side_effect=PermissionError(f"cannot read {root}"),
            ):
                try:
                    inventory = collect_inputs([root])
                except OSError as exc:
                    self.fail(f"directory error escaped collection: {type(exc).__name__}")
        entry = inventory.entries[0]
        self.assertEqual(root.name, entry.relative_path)
        self.assertEqual("blocked", entry.status)
        self.assertEqual("filesystem_access_failed", entry.reason)
        self.assertNotIn(temp, entry.reason or "")

    def test_file_disappearance_after_descriptor_stat_is_reported_as_blocked(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "vanishing.csv"
            path.write_text("value\n1\n", encoding="utf-8")
            real_stat = os.stat
            removed = False

            def stat_then_remove(*args, **kwargs) -> os.stat_result:
                nonlocal removed
                file_stat = real_stat(*args, **kwargs)
                candidate = args[0]
                if (
                    candidate == path.name
                    and kwargs.get("dir_fd") is not None
                    and not removed
                ):
                    path.unlink()
                    removed = True
                return file_stat

            with mock.patch(
                "data_audit_toolkit.traversal.os.stat",
                side_effect=stat_then_remove,
            ):
                try:
                    inventory = collect_inputs([path])
                except OSError as exc:
                    self.fail(f"disappearance escaped collection: {type(exc).__name__}")
        entry = inventory.entries[0]
        self.assertEqual("blocked", entry.status)
        self.assertEqual("file_read_failed", entry.reason)
        self.assertIsNone(entry.sha256)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes unavailable")
    def test_special_file_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fifo = Path(temp) / "input.csv"
            os.mkfifo(fifo)
            inventory = collect_inputs([Path(temp)])
        self.assertEqual("special_file_blocked", inventory.entries[0].reason)
