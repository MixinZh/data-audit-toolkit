from __future__ import annotations

import io
import os
import struct
import tempfile
import unittest
import warnings
import zipfile
import zlib
from pathlib import Path
from unittest import mock

from data_audit_toolkit import archive as archive_module
from data_audit_toolkit.archive import UnsafeArchiveError, read_xlsx_table, validate_zip_archive
from data_audit_toolkit.engine import scan_paths
from data_audit_toolkit.models import ScanLimits


_CONTENT_TYPES_NS = (
    "http://schemas.openxmlformats.org/package/2006/content-types"
)
_PACKAGE_RELATIONSHIPS_NS = (
    "http://schemas.openxmlformats.org/package/2006/relationships"
)
_OFFICE_RELATIONSHIPS_NS = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
)
_SPREADSHEET_NS = (
    "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
)
_WORKSHEET_RELATIONSHIP = f"{_OFFICE_RELATIONSHIPS_NS}/worksheet"
_CHARTSHEET_RELATIONSHIP = f"{_OFFICE_RELATIONSHIPS_NS}/chartsheet"


def _worksheet(
    cell_reference: str = "A1",
    value: str = "42",
    padding: int = 0,
) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData><row r="1"><c r="{cell_reference}"><v>{value}</v></c></row></sheetData>'
        f"<!--{'A' * padding}-->"
        "</worksheet>"
    )


def _coherent_xlsx_members(
    *,
    worksheet: str | None = None,
    worksheet_target: str = "worksheets/data.xml",
    relationship_type: str = _WORKSHEET_RELATIONSHIP,
    orphan_worksheet: str | None = None,
) -> list[tuple[str, str]]:
    workbook = (
        f'<workbook xmlns="{_SPREADSHEET_NS}" '
        f'xmlns:r="{_OFFICE_RELATIONSHIPS_NS}">'
        '<sheets><sheet name="Data" sheetId="1" r:id="rId1"/></sheets>'
        "</workbook>"
    )
    workbook_relationships = (
        f'<Relationships xmlns="{_PACKAGE_RELATIONSHIPS_NS}">'
        f'<Relationship Id="rId1" Type="{relationship_type}" '
        f'Target="{worksheet_target}"/>'
        "</Relationships>"
    )
    package_relationships = (
        f'<Relationships xmlns="{_PACKAGE_RELATIONSHIPS_NS}">'
        f'<Relationship Id="rId1" '
        f'Type="{_OFFICE_RELATIONSHIPS_NS}/officeDocument" '
        'Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    target_part = f"xl/{worksheet_target}"
    target_content_type = (
        "application/vnd.openxmlformats-officedocument."
        "spreadsheetml.worksheet+xml"
        if relationship_type == _WORKSHEET_RELATIONSHIP
        else
        "application/vnd.openxmlformats-officedocument."
        "spreadsheetml.chartsheet+xml"
    )
    content_types = (
        f'<Types xmlns="{_CONTENT_TYPES_NS}">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.'
        'spreadsheetml.sheet.main+xml"/>'
        f'<Override PartName="/{target_part}" '
        f'ContentType="{target_content_type}"/>'
        "</Types>"
    )
    members = [
        (
            target_part,
            worksheet if worksheet is not None else _worksheet(),
        ),
        ("[Content_Types].xml", content_types),
        ("_rels/.rels", package_relationships),
        ("xl/workbook.xml", workbook),
        ("xl/_rels/workbook.xml.rels", workbook_relationships),
    ]
    if orphan_worksheet is not None:
        members.append(
            ("xl/worksheets/sheet9.xml", orphan_worksheet)
        )
    return members


def _write_coherent_xlsx(
    path: Path,
    *,
    worksheet: str | None = None,
    worksheet_target: str = "worksheets/data.xml",
    relationship_type: str = _WORKSHEET_RELATIONSHIP,
    orphan_worksheet: str | None = None,
    first_member: tuple[str, str] | None = None,
    compression: int = zipfile.ZIP_STORED,
) -> None:
    with zipfile.ZipFile(path, "w", compression=compression) as handle:
        if first_member is not None:
            handle.writestr(*first_member)
        for member in _coherent_xlsx_members(
            worksheet=worksheet,
            worksheet_target=worksheet_target,
            relationship_type=relationship_type,
            orphan_worksheet=orphan_worksheet,
        ):
            handle.writestr(*member)


def _write_workbook(
    path: Path,
    *,
    worksheet: str | None = None,
    first_member: tuple[str, str] | None = None,
    compression: int = zipfile.ZIP_STORED,
) -> None:
    _write_coherent_xlsx(
        path,
        worksheet=worksheet,
        worksheet_target="worksheets/sheet1.xml",
        first_member=first_member,
        compression=compression,
    )


def _patch_first_member(
    path: Path,
    *,
    encrypted: bool = False,
    compress_type: int | None = None,
    compress_size: int | None = None,
    file_size: int | None = None,
    crc: int | None = None,
) -> None:
    payload = bytearray(path.read_bytes())
    local_offset = payload.index(b"PK\x03\x04")
    central_offset = payload.index(b"PK\x01\x02")
    if encrypted:
        local_flags = struct.unpack_from("<H", payload, local_offset + 6)[0]
        central_flags = struct.unpack_from("<H", payload, central_offset + 8)[0]
        struct.pack_into("<H", payload, local_offset + 6, local_flags | 1)
        struct.pack_into("<H", payload, central_offset + 8, central_flags | 1)
    if compress_type is not None:
        struct.pack_into("<H", payload, local_offset + 8, compress_type)
        struct.pack_into("<H", payload, central_offset + 10, compress_type)
    if crc is not None:
        struct.pack_into("<L", payload, local_offset + 14, crc)
        struct.pack_into("<L", payload, central_offset + 16, crc)
    if compress_size is not None:
        struct.pack_into("<L", payload, local_offset + 18, compress_size)
        struct.pack_into("<L", payload, central_offset + 20, compress_size)
    if file_size is not None:
        struct.pack_into("<L", payload, local_offset + 22, file_size)
        struct.pack_into("<L", payload, central_offset + 24, file_size)
    path.write_bytes(payload)


class _UnseekableBytesIO(io.BytesIO):
    def seek(self, *args: object, **kwargs: object) -> int:
        raise io.UnsupportedOperation("seek")


def _write_data_descriptor_workbook(path: Path) -> None:
    output = _UnseekableBytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as handle:
        for member in _coherent_xlsx_members(
            worksheet_target="worksheets/sheet1.xml",
        ):
            handle.writestr(*member)
    path.write_bytes(output.getvalue())


def _write_descriptor_collision_archive(
    path: Path,
    *,
    zip64: bool,
    signed: bool,
) -> None:
    signature_crc = 0x08074B50
    content = b"\xac\x0a\x7a\xd5"
    if zlib.crc32(content) != signature_crc:
        raise AssertionError("CRC fixture is invalid")
    output = _UnseekableBytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as handle:
        with handle.open("ignored.bin", "w", force_zip64=zip64) as member:
            member.write(content)
    payload = bytearray(output.getvalue())
    filename_size, extra_size = struct.unpack_from("<2H", payload, 26)
    descriptor_offset = 30 + filename_size + extra_size + len(content)
    central_offset = payload.index(b"PK\x01\x02")
    expected_descriptor_size = 24 if zip64 else 16
    if central_offset - descriptor_offset != expected_descriptor_size:
        raise AssertionError("unexpected descriptor fixture size")
    if payload[descriptor_offset:descriptor_offset + 4] != b"PK\x07\x08":
        raise AssertionError("expected signed data descriptor")
    if not signed:
        del payload[descriptor_offset:descriptor_offset + 4]
        end_record_offset = payload.index(b"PK\x05\x06")
        stored_central_offset = struct.unpack_from(
            "<L",
            payload,
            end_record_offset + 16,
        )[0]
        struct.pack_into(
            "<L",
            payload,
            end_record_offset + 16,
            stored_central_offset - 4,
        )
    path.write_bytes(payload)


def _read_all_validated_members(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        members = archive_module._validate_open_archive(
            archive,
            ScanLimits(),
        )
        return archive_module._read_validated_members(
            archive,
            members,
            ScanLimits(),
        )


class ArchiveSafetyTests(unittest.TestCase):
    def assert_engine_rejects(
        self,
        workbook: Path,
        reason: str,
        limits: ScanLimits = ScanLimits(),
    ) -> None:
        report = scan_paths([workbook], limits=limits)
        public_name = f"input-1-{workbook.name}"
        self.assertEqual([], report["scanned_files"])
        self.assertEqual([public_name], report["blocked_files"])
        self.assertEqual(
            [
                {
                    "file": public_name,
                    "reason": reason,
                    "meaning": (
                        "This container was inventoried but not checked because "
                        "it exceeded a safety boundary."
                    ),
                }
            ],
            report["not_checked"],
        )
        self.assertEqual([], report["findings"])

    def test_parent_path_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "unsafe.xlsx"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("../outside.xml", "<x/>")
            with self.assertRaisesRegex(UnsafeArchiveError, "archive_path_traversal"):
                validate_zip_archive(archive, ScanLimits())

    def test_uncompressed_limit_is_rejected_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "large.xlsx"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
                handle.writestr("xl/worksheets/sheet1.xml", "A" * 4096)
            limits = ScanLimits(max_archive_uncompressed_bytes=1024)
            with self.assertRaisesRegex(UnsafeArchiveError, "archive_uncompressed_bytes_exceeded"):
                validate_zip_archive(archive, limits)

    def test_entry_count_limit_is_rejected_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "many.xlsx"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("xl/worksheets/sheet1.xml", "<x/>")
                handle.writestr("xl/worksheets/sheet2.xml", "<x/>")
            limits = ScanLimits(max_archive_entries=1)
            with self.assertRaisesRegex(UnsafeArchiveError, "archive_entries_exceeded"):
                validate_zip_archive(archive, limits)

    def test_single_entry_size_limit_is_rejected_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "entry-large.xlsx"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("xl/worksheets/sheet1.xml", "A" * 32)
            limits = ScanLimits(max_archive_entry_bytes=16)
            with self.assertRaisesRegex(UnsafeArchiveError, "archive_entry_bytes_exceeded"):
                validate_zip_archive(archive, limits)

    def test_compression_ratio_limit_is_rejected_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "ratio.xlsx"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
                handle.writestr("xl/worksheets/sheet1.xml", "A" * 4096)
            limits = ScanLimits(max_archive_ratio=2)
            with self.assertRaisesRegex(UnsafeArchiveError, "archive_ratio_exceeded"):
                validate_zip_archive(archive, limits)

    def test_absolute_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "absolute.xlsx"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("/tmp/escape.xml", "<x/>")
            with self.assertRaisesRegex(UnsafeArchiveError, "archive_path_traversal"):
                validate_zip_archive(archive, ScanLimits())

    def test_bounded_reader_preserves_simple_numeric_cells(self) -> None:
        worksheet = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetData><row r="1"><c r="A1"><v>42</v></c></row></sheetData>'
            '</worksheet>'
        )
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "simple.xlsx"
            _write_workbook(workbook, worksheet=worksheet)
            sheets = read_xlsx_table(workbook, ScanLimits())
        self.assertEqual({"sheet1": [["42"]]}, sheets)

    def test_reader_scans_only_declared_supported_worksheets(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "declared.xlsx"
            _write_coherent_xlsx(
                workbook,
                worksheet=_worksheet(value="42"),
                orphan_worksheet=_worksheet(value="99"),
            )
            sheets = read_xlsx_table(workbook, ScanLimits())
        self.assertEqual({"sheet1": [["42"]]}, sheets)

    def test_incoherent_xlsx_packages_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archives = {
                "empty.xlsx": {},
                "arbitrary.xlsx": {"arbitrary.txt": "not a workbook"},
                "workbook-only.xlsx": {
                    "xl/workbook.xml": (
                        f'<workbook xmlns="{_SPREADSHEET_NS}"/>'
                    ),
                },
                "orphan-sheet.xlsx": {
                    "xl/worksheets/sheet1.xml": _worksheet(),
                },
            }
            for name, members in archives.items():
                workbook = root / name
                with zipfile.ZipFile(workbook, "w") as handle:
                    for member_name, content in members.items():
                        handle.writestr(member_name, content)
                with self.subTest(name=name):
                    report = scan_paths([workbook])
                    self.assertEqual([], report["scanned_files"])
                    self.assertEqual(
                        [f"input-1-{name}"],
                        report["blocked_files"],
                    )
                    self.assertEqual(
                        "xlsx_parse_failed",
                        report["not_checked"][0]["reason"],
                    )

    def test_no_declared_supported_worksheet_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "chartsheet-only.xlsx"
            _write_coherent_xlsx(
                workbook,
                relationship_type=_CHARTSHEET_RELATIONSHIP,
                worksheet_target="chartsheets/sheet1.xml",
            )
            report = scan_paths([workbook])
        self.assertEqual([], report["scanned_files"])
        self.assertEqual(
            ["input-1-chartsheet-only.xlsx"],
            report["blocked_files"],
        )
        self.assertEqual(
            "xlsx_unsupported_layout",
            report["not_checked"][0]["reason"],
        )

    def test_declared_xml_size_limit_is_rejected_before_parse(self) -> None:
        worksheet = (
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            "<sheetData/>"
            "</worksheet>"
        )
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "xml-large.xlsx"
            with zipfile.ZipFile(workbook, "w") as handle:
                handle.writestr("xl/worksheets/sheet1.xml", worksheet)
            limits = ScanLimits(max_xml_bytes=16)
            with self.assertRaisesRegex(UnsafeArchiveError, "xml_bytes_exceeded"):
                read_xlsx_table(workbook, limits)

    def test_unsafe_workbook_is_not_checked_without_partial_findings(self) -> None:
        worksheet = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetData><row r="1"><c r="A1"><v>42</v></c></row></sheetData>'
            '</worksheet>'
        )
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "unsafe.xlsx"
            with zipfile.ZipFile(workbook, "w") as handle:
                handle.writestr("xl/worksheets/sheet1.xml", worksheet)
                handle.writestr("../outside.xml", "<x/>")
            report = scan_paths([workbook])
        self.assertEqual([], report["scanned_files"])
        self.assertEqual(["input-1-unsafe.xlsx"], report["blocked_files"])
        self.assertEqual(
            [
                {
                    "file": "input-1-unsafe.xlsx",
                    "reason": "archive_path_traversal",
                    "meaning": (
                        "This container was inventoried but not checked because "
                        "it exceeded a safety boundary."
                    ),
                }
            ],
            report["not_checked"],
        )
        self.assertEqual([], report["findings"])

    def test_metadata_preflight_rejects_every_unsafe_member(self) -> None:
        cases = (
            ("duplicate", "archive_duplicate_entry"),
            ("encrypted", "archive_encrypted_entry"),
            ("unsupported", "archive_unsupported_compression"),
        )
        for case, expected_reason in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                workbook = Path(temp) / f"{case}.xlsx"
                if case == "duplicate":
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        with zipfile.ZipFile(workbook, "w") as handle:
                            handle.writestr("ignored.bin", "first")
                            handle.writestr("ignored.bin", "second")
                            handle.writestr(
                                "xl/worksheets/sheet1.xml",
                                _worksheet(),
                            )
                else:
                    _write_workbook(
                        workbook,
                        first_member=("ignored.bin", "ignored"),
                    )
                    _patch_first_member(
                        workbook,
                        encrypted=case == "encrypted",
                        compress_type=99 if case == "unsupported" else None,
                    )
                with self.assertRaisesRegex(
                    UnsafeArchiveError,
                    expected_reason,
                ):
                    validate_zip_archive(workbook, ScanLimits())

    def test_canonical_member_aliases_are_duplicate_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "aliases.xlsx"
            with zipfile.ZipFile(workbook, "w") as handle:
                handle.writestr(r"xl\sharedStrings.xml", "<x/>")
                handle.writestr("xl/sharedStrings.xml", "<x/>")
                handle.writestr("xl/worksheets/sheet1.xml", _worksheet())
            with self.assertRaisesRegex(
                UnsafeArchiveError,
                "archive_duplicate_entry",
            ):
                validate_zip_archive(workbook, ScanLimits())

    def test_windows_and_mixed_archive_paths_are_rejected(self) -> None:
        separator = chr(92)
        unsafe_names = (
            ".." + separator + "outside.xml",
            "C:" + separator + "tmp" + separator + "escape.xml",
            "C:" + "/" + "tmp/escape.xml",
            (
                separator * 2
                + "server"
                + separator
                + "share"
                + separator
                + "escape.xml"
            ),
            "xl/worksheets" + separator + ".." + separator + "outside.xml",
        )
        for unsafe_name in unsafe_names:
            with (
                self.subTest(name=unsafe_name),
                tempfile.TemporaryDirectory() as temp,
            ):
                workbook = Path(temp) / "unsafe.xlsx"
                _write_workbook(
                    workbook,
                    first_member=(unsafe_name, "<x/>"),
                )
                with self.assertRaisesRegex(
                    UnsafeArchiveError,
                    "archive_path_traversal",
                ):
                    validate_zip_archive(workbook, ScanLimits())

    def test_actual_archive_bounds_override_forged_declared_sizes(self) -> None:
        cases = (
            (
                "entry",
                ScanLimits(
                    max_archive_entry_bytes=64,
                    max_archive_uncompressed_bytes=10_000,
                    max_archive_ratio=10_000,
                    max_xml_bytes=10_000,
                ),
                "archive_entry_bytes_exceeded",
                zipfile.ZIP_STORED,
                256,
            ),
            (
                "total",
                ScanLimits(
                    max_archive_entry_bytes=10_000,
                    max_archive_uncompressed_bytes=64,
                    max_archive_ratio=10_000,
                    max_xml_bytes=10_000,
                ),
                "archive_uncompressed_bytes_exceeded",
                zipfile.ZIP_STORED,
                256,
            ),
            (
                "ratio",
                ScanLimits(
                    max_archive_entry_bytes=10_000,
                    max_archive_uncompressed_bytes=10_000,
                    max_archive_ratio=2,
                    max_xml_bytes=10_000,
                ),
                "archive_ratio_exceeded",
                zipfile.ZIP_DEFLATED,
                4_096,
            ),
            (
                "xml",
                ScanLimits(
                    max_archive_entry_bytes=10_000,
                    max_archive_uncompressed_bytes=10_000,
                    max_archive_ratio=10_000,
                    max_xml_bytes=64,
                ),
                "xml_bytes_exceeded",
                zipfile.ZIP_STORED,
                256,
            ),
            (
                "mismatch",
                ScanLimits(
                    max_archive_entry_bytes=10_000,
                    max_archive_uncompressed_bytes=10_000,
                    max_archive_ratio=10_000,
                    max_xml_bytes=10_000,
                ),
                "archive_entry_size_mismatch",
                zipfile.ZIP_STORED,
                0,
            ),
        )
        for case, limits, expected_reason, compression, padding in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                workbook = Path(temp) / f"{case}.xlsx"
                _write_workbook(
                    workbook,
                    worksheet=_worksheet(padding=padding),
                    compression=compression,
                )
                _patch_first_member(workbook, file_size=1)
                with self.assertRaisesRegex(
                    UnsafeArchiveError,
                    expected_reason,
                ):
                    read_xlsx_table(workbook, limits)

    def test_ignored_member_actual_bytes_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "ignored-overflow.xlsx"
            _write_workbook(
                workbook,
                first_member=("ignored.bin", "A" * 256),
            )
            _patch_first_member(workbook, file_size=1)
            limits = ScanLimits(
                max_archive_entry_bytes=64,
                max_archive_uncompressed_bytes=10_000,
                max_archive_ratio=10_000,
                max_xml_bytes=10_000,
            )
            with self.assertRaisesRegex(
                UnsafeArchiveError,
                "archive_entry_bytes_exceeded",
            ):
                read_xlsx_table(workbook, limits)

    def test_valid_data_descriptor_workbook_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "descriptor.xlsx"
            _write_data_descriptor_workbook(workbook)
            sheets = read_xlsx_table(workbook, ScanLimits())
        self.assertEqual({"sheet1": [["42"]]}, sheets)

    def test_forged_data_descriptor_sizes_are_unsafe(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "forged-descriptor.xlsx"
            _write_data_descriptor_workbook(workbook)
            _patch_first_member(
                workbook,
                compress_size=1,
                file_size=1,
                crc=zlib.crc32(b"<"),
            )
            with self.assertRaisesRegex(
                UnsafeArchiveError,
                "archive_entry_size_mismatch",
            ):
                read_xlsx_table(workbook, ScanLimits())

    def test_unsigned_32_bit_descriptor_crc_signature_collision_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "unsigned-32.xlsx"
            _write_descriptor_collision_archive(
                workbook,
                zip64=False,
                signed=False,
            )
            retained = _read_all_validated_members(workbook)
        self.assertEqual({}, retained)

    def test_unsigned_zip64_descriptor_crc_signature_collision_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "unsigned-zip64.xlsx"
            _write_descriptor_collision_archive(
                workbook,
                zip64=True,
                signed=False,
            )
            retained = _read_all_validated_members(workbook)
        self.assertEqual({}, retained)

    def test_signed_descriptor_variants_remain_valid(self) -> None:
        for zip64 in (False, True):
            with self.subTest(zip64=zip64), tempfile.TemporaryDirectory() as temp:
                workbook = Path(temp) / "signed.xlsx"
                _write_descriptor_collision_archive(
                    workbook,
                    zip64=zip64,
                    signed=True,
                )
                retained = _read_all_validated_members(workbook)
            self.assertEqual({}, retained)

    def test_sparse_worksheet_expansion_is_rejected_before_allocation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "sparse.xlsx"
            _write_workbook(
                workbook,
                worksheet=_worksheet(cell_reference="XFD64"),
            )
            with self.assertRaisesRegex(
                UnsafeArchiveError,
                "worksheet_dimensions_exceeded",
            ):
                read_xlsx_table(workbook, ScanLimits())

    def test_out_of_range_cell_reference_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "out-of-range.xlsx"
            _write_workbook(
                workbook,
                worksheet=_worksheet(cell_reference="XFE1"),
            )
            with self.assertRaisesRegex(
                UnsafeArchiveError,
                "worksheet_dimensions_exceeded",
            ):
                read_xlsx_table(workbook, ScanLimits())

    def test_xlsx_validation_and_reads_use_one_open_archive_handle(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workbook = Path(temp) / "same-handle.xlsx"
            replacement = Path(temp) / "replacement.xlsx"
            _write_workbook(workbook, worksheet=_worksheet(value="42"))
            _write_workbook(replacement, worksheet=_worksheet(value="99"))
            original_infolist = zipfile.ZipFile.infolist
            replaced = False

            def replace_after_infolist(
                archive: zipfile.ZipFile,
            ) -> list[zipfile.ZipInfo]:
                nonlocal replaced
                infos = original_infolist(archive)
                if not replaced and Path(archive.filename) == workbook:
                    os.replace(replacement, workbook)
                    replaced = True
                return infos

            with mock.patch.object(
                zipfile.ZipFile,
                "infolist",
                autospec=True,
                side_effect=replace_after_infolist,
            ):
                sheets = read_xlsx_table(workbook, ScanLimits())
        self.assertTrue(replaced)
        self.assertEqual({"sheet1": [["42"]]}, sheets)

    def test_new_unsafe_reasons_have_exact_engine_coverage_shape(self) -> None:
        cases = (
            ("duplicate", "archive_duplicate_entry", ScanLimits()),
            ("encrypted", "archive_encrypted_entry", ScanLimits()),
            ("unsupported", "archive_unsupported_compression", ScanLimits()),
            (
                "declared-entry-count",
                "archive_entries_exceeded",
                ScanLimits(max_archive_entries=1),
            ),
            ("windows-path", "archive_path_traversal", ScanLimits()),
            ("dimensions", "worksheet_dimensions_exceeded", ScanLimits()),
            ("actual-size", "archive_entry_size_mismatch", ScanLimits()),
            (
                "actual-entry-limit",
                "archive_entry_bytes_exceeded",
                ScanLimits(
                    max_archive_entry_bytes=64,
                    max_archive_uncompressed_bytes=10_000,
                    max_archive_ratio=10_000,
                    max_xml_bytes=10_000,
                ),
            ),
            (
                "actual-total-limit",
                "archive_uncompressed_bytes_exceeded",
                ScanLimits(
                    max_archive_entry_bytes=10_000,
                    max_archive_uncompressed_bytes=64,
                    max_archive_ratio=10_000,
                    max_xml_bytes=10_000,
                ),
            ),
            (
                "actual-ratio-limit",
                "archive_ratio_exceeded",
                ScanLimits(
                    max_archive_entry_bytes=10_000,
                    max_archive_uncompressed_bytes=10_000,
                    max_archive_ratio=2,
                    max_xml_bytes=10_000,
                ),
            ),
            (
                "actual-xml-limit",
                "xml_bytes_exceeded",
                ScanLimits(
                    max_archive_entry_bytes=10_000,
                    max_archive_uncompressed_bytes=10_000,
                    max_archive_ratio=10_000,
                    max_xml_bytes=64,
                ),
            ),
        )
        for case, expected_reason, limits in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                workbook = Path(temp) / f"{case}.xlsx"
                if case == "duplicate":
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        with zipfile.ZipFile(workbook, "w") as handle:
                            handle.writestr("ignored.bin", "first")
                            handle.writestr("ignored.bin", "second")
                            handle.writestr(
                                "xl/worksheets/sheet1.xml",
                                _worksheet(),
                            )
                elif case in {"encrypted", "unsupported"}:
                    _write_workbook(
                        workbook,
                        first_member=("ignored.bin", "ignored"),
                    )
                    _patch_first_member(
                        workbook,
                        encrypted=case == "encrypted",
                        compress_type=99 if case == "unsupported" else None,
                    )
                elif case == "declared-entry-count":
                    _write_workbook(
                        workbook,
                        first_member=("ignored.bin", "ignored"),
                    )
                elif case == "windows-path":
                    _write_workbook(
                        workbook,
                        first_member=(r"..\outside.xml", "<x/>"),
                    )
                elif case == "dimensions":
                    _write_workbook(
                        workbook,
                        worksheet=_worksheet(cell_reference="XFE1"),
                    )
                elif case.startswith("actual-"):
                    compression = (
                        zipfile.ZIP_DEFLATED
                        if case == "actual-ratio-limit"
                        else zipfile.ZIP_STORED
                    )
                    padding = (
                        4_096
                        if case == "actual-ratio-limit"
                        else 256
                    )
                    _write_workbook(
                        workbook,
                        worksheet=_worksheet(padding=padding),
                        compression=compression,
                    )
                    _patch_first_member(workbook, file_size=1)
                else:
                    _write_workbook(workbook)
                    _patch_first_member(workbook, file_size=1)
                self.assert_engine_rejects(workbook, expected_reason, limits)
