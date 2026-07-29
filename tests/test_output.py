from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from data_audit_toolkit import output as output_module
from data_audit_toolkit.output import OutputWriteError, write_report_atomic


class OutputTests(unittest.TestCase):
    def test_existing_output_requires_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "report.json"
            target.write_text("original", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                write_report_atomic({"schema_version": "data-audit-v1"}, target)
            self.assertEqual("original", target.read_text(encoding="utf-8"))

    def test_atomic_write_produces_complete_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "report.json"
            write_report_atomic({"schema_version": "data-audit-v1"}, target)
            self.assertEqual(
                "data-audit-v1",
                json.loads(target.read_text())["schema_version"],
            )
            self.assertEqual([], list(Path(temp).glob("*.tmp")))

    def test_parent_directories_are_created_and_target_is_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "nested" / ".." / "reports" / "report.json"
            written = write_report_atomic({"schema_version": "data-audit-v1"}, target)
            self.assertEqual(target.resolve(), written)
            self.assertTrue(written.is_file())

    def test_output_parent_resolves_symlink_before_dotdot(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lexical_root = root / "lexical"
            actual_root = root / "actual"
            actual_child = actual_root / "child"
            lexical_root.mkdir()
            actual_child.mkdir(parents=True)
            (lexical_root / "jump").symlink_to(
                actual_child,
                target_is_directory=True,
            )
            target = lexical_root / "jump" / ".." / "report.json"
            expected = actual_root / "report.json"

            written = write_report_atomic(
                {"schema_version": "data-audit-v1"},
                target,
            )

            self.assertEqual(expected.resolve(), written)
            self.assertTrue(target.is_file())
            self.assertFalse((lexical_root / "report.json").exists())

    def test_overwrite_replaces_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "report.json"
            target.write_text("original", encoding="utf-8")
            write_report_atomic(
                {"schema_version": "data-audit-v1"},
                target,
                overwrite=True,
            )
            self.assertEqual(
                {"schema_version": "data-audit-v1"},
                json.loads(target.read_text(encoding="utf-8")),
            )

    def test_overwrite_rejects_leaf_symlink_without_touching_referent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            referent = root / "protected.txt"
            target = root / "report.json"
            referent.write_text("protected", encoding="utf-8")
            target.symlink_to(referent)
            with self.assertRaisesRegex(
                ValueError,
                "output path must not be a symlink",
            ):
                write_report_atomic(
                    {"schema_version": "data-audit-v1"},
                    target,
                    overwrite=True,
                )
            self.assertTrue(target.is_symlink())
            self.assertEqual("protected", referent.read_text(encoding="utf-8"))

    def test_no_overwrite_does_not_clobber_concurrently_created_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "report.json"
            real_fsync = os.fsync
            competitor_created = False

            def create_competitor(descriptor: int) -> None:
                nonlocal competitor_created
                real_fsync(descriptor)
                target.write_text("competitor", encoding="utf-8")
                competitor_created = True

            with (
                mock.patch(
                    "data_audit_toolkit.output.os.fsync",
                    side_effect=create_competitor,
                ),
                self.assertRaises(FileExistsError),
            ):
                write_report_atomic({"schema_version": "data-audit-v1"}, target)
            self.assertTrue(competitor_created)
            self.assertEqual("competitor", target.read_text(encoding="utf-8"))
            self.assertEqual([], list(Path(temp).glob("*.tmp")))

    def test_serialization_failure_removes_partial_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "report.json"
            with self.assertRaises(TypeError):
                write_report_atomic({"not_json": object()}, target)
            self.assertFalse(target.exists())
            self.assertEqual([], list(Path(temp).glob("*.tmp")))

    def test_nonfinite_number_is_rejected_as_nonstandard_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "report.json"
            with self.assertRaises(ValueError):
                write_report_atomic({"nonfinite": float("inf")}, target)
            self.assertFalse(target.exists())
            self.assertEqual([], list(Path(temp).glob("*.tmp")))

    def test_replace_failure_removes_temporary_file_and_preserves_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "report.json"
            target.write_text("original", encoding="utf-8")
            with (
                mock.patch(
                    "data_audit_toolkit.output.os.replace",
                    side_effect=OSError("replace failed"),
                ),
                self.assertRaises(OSError),
            ):
                write_report_atomic(
                    {"schema_version": "data-audit-v1"},
                    target,
                    overwrite=True,
                )
            self.assertEqual("original", target.read_text(encoding="utf-8"))
            self.assertEqual([], list(Path(temp).glob("*.tmp")))

    def test_no_overwrite_syncs_publication_and_cleanup_directory_entries(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "report.json"
            events: list[str] = []
            real_fsync = os.fsync
            real_link = os.link
            real_unlink = os.unlink

            def record_fsync(descriptor: int) -> None:
                mode = os.fstat(descriptor).st_mode
                events.append(
                    "sync-directory" if stat.S_ISDIR(mode) else "sync-file"
                )
                real_fsync(descriptor)

            def record_link(*args, **kwargs):
                events.append("link-target")
                return real_link(*args, **kwargs)

            def record_unlink(path, *args, **kwargs):
                if str(path).endswith(".tmp"):
                    events.append("unlink-temporary")
                return real_unlink(path, *args, **kwargs)

            with (
                mock.patch(
                    "data_audit_toolkit.output.os.fsync",
                    side_effect=record_fsync,
                ),
                mock.patch(
                    "data_audit_toolkit.output.os.link",
                    side_effect=record_link,
                ),
                mock.patch(
                    "data_audit_toolkit.output.os.unlink",
                    side_effect=record_unlink,
                ),
            ):
                write_report_atomic({"schema_version": "data-audit-v1"}, target)

            self.assertEqual(
                [
                    "sync-file",
                    "link-target",
                    "sync-directory",
                    "unlink-temporary",
                    "sync-directory",
                ],
                events,
            )
            self.assertEqual(
                "data-audit-v1",
                json.loads(target.read_text(encoding="utf-8"))["schema_version"],
            )

    def test_overwrite_syncs_parent_directory_after_replace(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "report.json"
            target.write_text("original", encoding="utf-8")
            events: list[str] = []
            real_fsync = os.fsync
            real_replace = os.replace

            def record_fsync(descriptor: int) -> None:
                mode = os.fstat(descriptor).st_mode
                events.append(
                    "sync-directory" if stat.S_ISDIR(mode) else "sync-file"
                )
                real_fsync(descriptor)

            def record_replace(*args, **kwargs):
                events.append("replace-target")
                return real_replace(*args, **kwargs)

            with (
                mock.patch(
                    "data_audit_toolkit.output.os.fsync",
                    side_effect=record_fsync,
                ),
                mock.patch(
                    "data_audit_toolkit.output.os.replace",
                    side_effect=record_replace,
                ),
            ):
                write_report_atomic(
                    {"schema_version": "data-audit-v1"},
                    target,
                    overwrite=True,
                )

            self.assertEqual(
                ["sync-file", "replace-target", "sync-directory"],
                events,
            )
            self.assertEqual(
                "data-audit-v1",
                json.loads(target.read_text(encoding="utf-8"))["schema_version"],
            )

    def test_no_overwrite_temp_cleanup_failure_keeps_published_report(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "report.json"
            real_unlink = os.unlink

            def fail_temporary_unlink(path, *args, **kwargs):
                if str(path).endswith(".tmp"):
                    raise OSError("injected temporary unlink failure")
                return real_unlink(path, *args, **kwargs)

            with mock.patch(
                "data_audit_toolkit.output.os.unlink",
                side_effect=fail_temporary_unlink,
            ):
                try:
                    written = write_report_atomic(
                        {"schema_version": "data-audit-v1"},
                        target,
                    )
                except OutputWriteError:
                    written = None

            temporary_links = list(root.glob(".data-audit-*.tmp"))
            self.assertEqual(target.resolve(), written)
            self.assertEqual(
                "data-audit-v1",
                json.loads(target.read_text(encoding="utf-8"))["schema_version"],
            )
            self.assertEqual(1, len(temporary_links))
            self.assertTrue(os.path.samefile(target, temporary_links[0]))

    def test_no_overwrite_cleanup_race_never_unlinks_competitor(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "report.json"
            competitor_source = root / "competitor"
            competitor_source.write_text("competitor", encoding="utf-8")
            real_unlink = os.unlink
            real_stat_output_leaf = output_module._stat_output_leaf
            cleanup_failed = False
            competitor_installed = False

            def fail_first_temporary_unlink(path, *args, **kwargs):
                nonlocal cleanup_failed
                if str(path).endswith(".tmp") and not cleanup_failed:
                    cleanup_failed = True
                    raise OSError("injected temporary unlink failure")
                return real_unlink(path, *args, **kwargs)

            def stat_then_install_competitor(prepared_target):
                nonlocal competitor_installed
                file_stat = real_stat_output_leaf(prepared_target)
                if cleanup_failed and not competitor_installed:
                    os.replace(competitor_source, target)
                    competitor_installed = True
                return file_stat

            with (
                mock.patch(
                    "data_audit_toolkit.output.os.unlink",
                    side_effect=fail_first_temporary_unlink,
                ),
                mock.patch.object(
                    output_module,
                    "_stat_output_leaf",
                    side_effect=stat_then_install_competitor,
                ),
            ):
                try:
                    written = write_report_atomic(
                        {"schema_version": "data-audit-v1"},
                        target,
                    )
                except OutputWriteError:
                    written = None

            self.assertTrue(cleanup_failed)
            self.assertTrue(competitor_installed)
            self.assertEqual(target.resolve(), written)
            self.assertEqual("competitor", target.read_text(encoding="utf-8"))
            temporary_links = list(root.glob(".data-audit-*.tmp"))
            self.assertEqual(1, len(temporary_links))
            self.assertEqual(
                "data-audit-v1",
                json.loads(
                    temporary_links[0].read_text(encoding="utf-8")
                )["schema_version"],
            )
