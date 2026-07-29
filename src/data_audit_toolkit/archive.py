from __future__ import annotations

import re
import struct
import xml.etree.ElementTree as ET
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from .models import ScanLimits


_LOCAL_HEADER = struct.Struct("<4s5H3L2H")
_LOCAL_HEADER_SIGNATURE = b"PK\x03\x04"
_SUPPORTED_COMPRESSION = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
_MAX_XLSX_ROW = 1_048_576
_MAX_XLSX_COLUMN = 16_384
_MAX_WORKSHEET_MATERIALIZED_CELLS = 1_000_000
_READ_CHUNK_BYTES = 64 * 1024
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
_OFFICE_DOCUMENT_RELATIONSHIP = (
    f"{_OFFICE_RELATIONSHIPS_NS}/officeDocument"
)
_WORKSHEET_RELATIONSHIP = f"{_OFFICE_RELATIONSHIPS_NS}/worksheet"
_SHARED_STRINGS_RELATIONSHIP = (
    f"{_OFFICE_RELATIONSHIPS_NS}/sharedStrings"
)
_WORKBOOK_CONTENT_TYPE = (
    "application/vnd.openxmlformats-officedocument."
    "spreadsheetml.sheet.main+xml"
)
_WORKSHEET_CONTENT_TYPE = (
    "application/vnd.openxmlformats-officedocument."
    "spreadsheetml.worksheet+xml"
)
_SHARED_STRINGS_CONTENT_TYPE = (
    "application/vnd.openxmlformats-officedocument."
    "spreadsheetml.sharedStrings+xml"
)
_CONTENT_TYPES_PART = "[Content_Types].xml"
_PACKAGE_RELATIONSHIPS_PART = "_rels/.rels"
_WORKBOOK_PART = "xl/workbook.xml"
_WORKBOOK_RELATIONSHIPS_PART = "xl/_rels/workbook.xml.rels"


class UnsafeArchiveError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class _ValidatedMember:
    info: zipfile.ZipInfo
    name: str
    data_offset: int
    data_region_end: int


def _canonical_member_name(filename: str) -> str:
    if "/" in filename and "\\" in filename:
        raise UnsafeArchiveError("archive_path_traversal")
    windows_path = PureWindowsPath(filename)
    normalized = filename.replace("\\", "/")
    posix_path = PurePosixPath(normalized)
    if (
        windows_path.drive
        or windows_path.is_absolute()
        or posix_path.is_absolute()
        or ".." in posix_path.parts
    ):
        raise UnsafeArchiveError("archive_path_traversal")
    canonical = posix_path.as_posix()
    if normalized.endswith("/") and canonical != ".":
        canonical += "/"
    return canonical


def _read_exact(handle: object, size: int) -> bytes:
    content = bytearray()
    while len(content) < size:
        chunk = handle.read(size - len(content))
        if not chunk:
            raise UnsafeArchiveError("archive_entry_size_mismatch")
        content.extend(chunk)
    return bytes(content)


def _validate_open_archive(
    archive: zipfile.ZipFile,
    limits: ScanLimits,
) -> tuple[_ValidatedMember, ...]:
    infos = tuple(archive.infolist())
    canonical_names: list[str] = []
    seen_names: set[str] = set()
    for info in infos:
        canonical_name = _canonical_member_name(info.filename)
        if canonical_name in seen_names:
            raise UnsafeArchiveError("archive_duplicate_entry")
        seen_names.add(canonical_name)
        canonical_names.append(canonical_name)
    if len(infos) > limits.max_archive_entries:
        raise UnsafeArchiveError("archive_entries_exceeded")
    for info in infos:
        if info.flag_bits & 1:
            raise UnsafeArchiveError("archive_encrypted_entry")
        if info.compress_type not in _SUPPORTED_COMPRESSION:
            raise UnsafeArchiveError("archive_unsupported_compression")
        if info.file_size > limits.max_archive_entry_bytes:
            raise UnsafeArchiveError("archive_entry_bytes_exceeded")
    if sum(info.file_size for info in infos) > limits.max_archive_uncompressed_bytes:
        raise UnsafeArchiveError("archive_uncompressed_bytes_exceeded")
    for info in infos:
        ratio = info.file_size / max(info.compress_size, 1)
        if ratio > limits.max_archive_ratio:
            raise UnsafeArchiveError("archive_ratio_exceeded")

    if archive.fp is None:
        raise UnsafeArchiveError("archive_entry_size_mismatch")
    ordered = sorted(
        zip(infos, canonical_names),
        key=lambda item: item[0].header_offset,
    )
    if len({info.header_offset for info, _ in ordered}) != len(ordered):
        raise UnsafeArchiveError("archive_entry_size_mismatch")
    end_offsets = [
        ordered[index + 1][0].header_offset
        if index + 1 < len(ordered)
        else archive.start_dir
        for index in range(len(ordered))
    ]
    validated_by_offset: dict[int, _ValidatedMember] = {}
    for (info, canonical_name), data_region_end in zip(ordered, end_offsets):
        archive.fp.seek(info.header_offset)
        header = _read_exact(archive.fp, _LOCAL_HEADER.size)
        (
            signature,
            _extract_version,
            local_flags,
            local_compression,
            _modified_time,
            _modified_date,
            local_crc,
            local_compressed_size,
            local_file_size,
            filename_size,
            extra_size,
        ) = _LOCAL_HEADER.unpack(header)
        if signature != _LOCAL_HEADER_SIGNATURE:
            raise UnsafeArchiveError("archive_entry_size_mismatch")
        data_offset = info.header_offset + _LOCAL_HEADER.size + filename_size + extra_size
        if data_offset > data_region_end:
            raise UnsafeArchiveError("archive_entry_size_mismatch")
        filename_bytes = _read_exact(archive.fp, filename_size)
        _read_exact(archive.fp, extra_size)
        encoding = "utf-8" if local_flags & 0x800 else "cp437"
        try:
            local_name = _canonical_member_name(filename_bytes.decode(encoding))
        except UnicodeDecodeError as exc:
            raise UnsafeArchiveError("archive_entry_size_mismatch") from exc
        if local_flags & 1:
            raise UnsafeArchiveError("archive_encrypted_entry")
        if local_compression not in _SUPPORTED_COMPRESSION:
            raise UnsafeArchiveError("archive_unsupported_compression")
        if (
            local_name != canonical_name
            or local_flags != info.flag_bits
            or local_compression != info.compress_type
        ):
            raise UnsafeArchiveError("archive_entry_size_mismatch")
        uses_data_descriptor = bool(local_flags & 0x8)
        uses_zip64_sizes = (
            local_compressed_size == 0xFFFFFFFF
            or local_file_size == 0xFFFFFFFF
        )
        if not uses_data_descriptor and not uses_zip64_sizes:
            if (
                local_crc != info.CRC
                or local_compressed_size != info.compress_size
                or local_file_size != info.file_size
            ):
                raise UnsafeArchiveError("archive_entry_size_mismatch")
        validated_by_offset[info.header_offset] = _ValidatedMember(
            info=info,
            name=canonical_name,
            data_offset=data_offset,
            data_region_end=data_region_end,
        )
    return tuple(validated_by_offset[info.header_offset] for info in infos)


def validate_zip_archive(
    path: Path,
    limits: ScanLimits,
) -> tuple[zipfile.ZipInfo, ...]:
    with zipfile.ZipFile(path) as archive:
        return tuple(
            member.info
            for member in _validate_open_archive(archive, limits)
        )


def _is_xlsx_xml_part(name: str) -> bool:
    return (
        name
        in {
            _CONTENT_TYPES_PART,
            _PACKAGE_RELATIONSHIPS_PART,
            _WORKBOOK_PART,
            _WORKBOOK_RELATIONSHIPS_PART,
        }
        or (
            name.startswith("xl/worksheets/")
            and name.endswith(".xml")
        )
        or (
            name.startswith("xl/")
            and name.endswith("sharedStrings.xml")
        )
    )


def _validate_data_descriptor(
    handle: object,
    descriptor_offset: int,
    data_region_end: int,
    info: zipfile.ZipInfo,
) -> None:
    descriptor_size = data_region_end - descriptor_offset
    if descriptor_size not in {12, 16, 20, 24}:
        raise UnsafeArchiveError("archive_entry_size_mismatch")
    handle.seek(descriptor_offset)
    descriptor = _read_exact(handle, descriptor_size)
    if descriptor_size in {16, 24}:
        if not descriptor.startswith(b"PK\x07\x08"):
            raise UnsafeArchiveError("archive_entry_size_mismatch")
        descriptor = descriptor[4:]
    if len(descriptor) == 12:
        crc, compressed_size, file_size = struct.unpack("<3L", descriptor)
    elif len(descriptor) == 20:
        crc, compressed_size, file_size = struct.unpack("<L2Q", descriptor)
    else:
        raise UnsafeArchiveError("archive_entry_size_mismatch")
    if (
        crc != info.CRC
        or compressed_size != info.compress_size
        or file_size != info.file_size
    ):
        raise UnsafeArchiveError("archive_entry_size_mismatch")


def _read_validated_members(
    archive: zipfile.ZipFile,
    members: tuple[_ValidatedMember, ...],
    limits: ScanLimits,
) -> dict[str, bytes]:
    if archive.fp is None:
        raise UnsafeArchiveError("archive_entry_size_mismatch")
    retained: dict[str, bytes] = {}
    actual_total = 0
    first_integrity_mismatch: str | None = None

    for member in members:
        info = member.info
        keep_content = _is_xlsx_xml_part(member.name)
        content_chunks: list[bytes] = []
        actual_size = 0
        actual_crc = 0

        def account(content: bytes) -> None:
            nonlocal actual_crc, actual_size, actual_total
            if not content:
                return
            actual_size += len(content)
            actual_total += len(content)
            if actual_size > limits.max_archive_entry_bytes:
                raise UnsafeArchiveError("archive_entry_bytes_exceeded")
            if actual_total > limits.max_archive_uncompressed_bytes:
                raise UnsafeArchiveError("archive_uncompressed_bytes_exceeded")
            if keep_content and actual_size > limits.max_xml_bytes:
                raise UnsafeArchiveError("xml_bytes_exceeded")
            actual_crc = zlib.crc32(content, actual_crc)
            if keep_content:
                content_chunks.append(content)

        archive.fp.seek(member.data_offset)
        data_region_size = member.data_region_end - member.data_offset
        if info.compress_type == zipfile.ZIP_STORED:
            compressed_to_read = (
                info.compress_size
                if info.flag_bits & 0x8
                else data_region_size
            )
            if compressed_to_read < 0 or compressed_to_read > data_region_size:
                raise UnsafeArchiveError("archive_entry_size_mismatch")
            compressed_remaining = compressed_to_read
            while compressed_remaining:
                chunk = _read_exact(
                    archive.fp,
                    min(_READ_CHUNK_BYTES, compressed_remaining),
                )
                compressed_remaining -= len(chunk)
                account(chunk)
            actual_compressed_size = compressed_to_read
        else:
            decompressor = zlib.decompressobj(-15)
            compressed_read = 0
            compressed_remaining = data_region_size
            try:
                while compressed_remaining and not decompressor.eof:
                    raw_chunk = _read_exact(
                        archive.fp,
                        min(_READ_CHUNK_BYTES, compressed_remaining),
                    )
                    compressed_remaining -= len(raw_chunk)
                    compressed_read += len(raw_chunk)
                    pending = raw_chunk
                    while pending and not decompressor.eof:
                        output = decompressor.decompress(
                            pending,
                            _READ_CHUNK_BYTES,
                        )
                        pending = decompressor.unconsumed_tail
                        account(output)
                if not decompressor.eof:
                    raise UnsafeArchiveError("archive_entry_size_mismatch")
                account(decompressor.flush())
            except zlib.error as exc:
                raise UnsafeArchiveError("archive_entry_size_mismatch") from exc
            actual_compressed_size = compressed_read - len(decompressor.unused_data)

        if info.flag_bits & 0x8:
            _validate_data_descriptor(
                archive.fp,
                member.data_offset + actual_compressed_size,
                member.data_region_end,
                info,
            )
        elif actual_compressed_size != data_region_size:
            first_integrity_mismatch = (
                first_integrity_mismatch or "archive_entry_size_mismatch"
            )
        if (
            actual_size / max(actual_compressed_size, 1)
            > limits.max_archive_ratio
        ):
            raise UnsafeArchiveError("archive_ratio_exceeded")
        if (
            actual_size != info.file_size
            or actual_compressed_size != info.compress_size
        ):
            first_integrity_mismatch = (
                first_integrity_mismatch or "archive_entry_size_mismatch"
            )
        elif actual_crc != info.CRC:
            first_integrity_mismatch = (
                first_integrity_mismatch or "archive_entry_size_mismatch"
            )
        if keep_content:
            retained[member.name] = b"".join(content_chunks)

    if first_integrity_mismatch is not None:
        raise UnsafeArchiveError(first_integrity_mismatch)
    return retained


def _cell_column(column_letters: str) -> int:
    column = 0
    for char in column_letters:
        column = column * 26 + ord(char) - 64
    return column


def _parse_worksheet(
    content: bytes,
    shared: list[str] | None,
) -> list[list[str]]:
    ns = {"a": _SPREADSHEET_NS}
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise UnsafeArchiveError("xlsx_parse_failed") from exc
    if root.tag != f"{{{_SPREADSHEET_NS}}}worksheet":
        raise UnsafeArchiveError("xlsx_parse_failed")
    grid: dict[tuple[int, int], str] = {}
    max_row = 0
    max_col = 0
    for cell in root.findall(".//a:c", ns):
        ref_attr = cell.attrib.get("r", "")
        match = re.fullmatch(r"([A-Z]+)(\d+)", ref_attr)
        if not match:
            continue
        column_letters, row_raw = match.groups()
        if len(column_letters) > 3 or len(row_raw) > 7:
            raise UnsafeArchiveError("worksheet_dimensions_exceeded")
        column = _cell_column(column_letters)
        row = int(row_raw)
        if (
            row < 1
            or row > _MAX_XLSX_ROW
            or column < 1
            or column > _MAX_XLSX_COLUMN
        ):
            raise UnsafeArchiveError("worksheet_dimensions_exceeded")
        next_max_row = max(max_row, row)
        next_max_col = max(max_col, column)
        if (
            next_max_row * next_max_col
            > _MAX_WORKSHEET_MATERIALIZED_CELLS
        ):
            raise UnsafeArchiveError("worksheet_dimensions_exceeded")
        value_node = cell.find("a:v", ns)
        value = (
            value_node.text
            if value_node is not None and value_node.text is not None
            else ""
        )
        cell_type = cell.attrib.get("t")
        if cell_type == "s":
            if (
                shared is None
                or not value.isdigit()
                or int(value) >= len(shared)
            ):
                raise UnsafeArchiveError("xlsx_parse_failed")
            value = shared[int(value)]
        elif cell_type == "inlineStr":
            value = "".join(
                node.text or ""
                for node in cell.findall(".//a:is/a:t", ns)
            )
        grid[(row, column)] = value
        max_row = next_max_row
        max_col = next_max_col
    return [
        [grid.get((row, column), "") for column in range(1, max_col + 1)]
        for row in range(1, max_row + 1)
    ]


def _required_xml_part(
    xml_parts: dict[str, bytes],
    name: str,
) -> bytes:
    try:
        return xml_parts[name]
    except KeyError as exc:
        raise UnsafeArchiveError("xlsx_parse_failed") from exc


def _parse_xml_root(
    xml_parts: dict[str, bytes],
    name: str,
) -> ET.Element:
    try:
        return ET.fromstring(_required_xml_part(xml_parts, name))
    except ET.ParseError as exc:
        raise UnsafeArchiveError("xlsx_parse_failed") from exc


def _relationship_records(
    root: ET.Element,
) -> dict[str, tuple[str, str, str | None]]:
    if root.tag != f"{{{_PACKAGE_RELATIONSHIPS_NS}}}Relationships":
        raise UnsafeArchiveError("xlsx_parse_failed")
    records: dict[str, tuple[str, str, str | None]] = {}
    for relationship in root:
        if relationship.tag != (
            f"{{{_PACKAGE_RELATIONSHIPS_NS}}}Relationship"
        ):
            raise UnsafeArchiveError("xlsx_parse_failed")
        relationship_id = relationship.attrib.get("Id", "")
        relationship_type = relationship.attrib.get("Type", "")
        target = relationship.attrib.get("Target", "")
        target_mode = relationship.attrib.get("TargetMode")
        if (
            not relationship_id
            or not relationship_type
            or not target
            or relationship_id in records
        ):
            raise UnsafeArchiveError("xlsx_parse_failed")
        records[relationship_id] = (
            relationship_type,
            target,
            target_mode,
        )
    return records


def _resolve_relationship_target(base_part: str, target: str) -> str:
    if (
        not target
        or "\\" in target
        or target.startswith("/")
        or ":" in target
        or "?" in target
        or "#" in target
        or "%" in target
    ):
        raise UnsafeArchiveError("xlsx_parse_failed")
    target_path = PurePosixPath(target)
    if ".." in target_path.parts:
        raise UnsafeArchiveError("xlsx_parse_failed")
    base_parent = PurePosixPath(base_part).parent
    resolved = base_parent.joinpath(target_path)
    canonical = resolved.as_posix()
    if canonical in {"", "."} or canonical.startswith("../"):
        raise UnsafeArchiveError("xlsx_parse_failed")
    return canonical


def _content_type_maps(
    root: ET.Element,
) -> tuple[dict[str, str], dict[str, str]]:
    if root.tag != f"{{{_CONTENT_TYPES_NS}}}Types":
        raise UnsafeArchiveError("xlsx_parse_failed")
    defaults: dict[str, str] = {}
    overrides: dict[str, str] = {}
    for child in root:
        if child.tag == f"{{{_CONTENT_TYPES_NS}}}Default":
            extension = child.attrib.get("Extension", "").casefold()
            content_type = child.attrib.get("ContentType", "")
            if not extension or not content_type or extension in defaults:
                raise UnsafeArchiveError("xlsx_parse_failed")
            defaults[extension] = content_type
        elif child.tag == f"{{{_CONTENT_TYPES_NS}}}Override":
            part_name = child.attrib.get("PartName", "")
            content_type = child.attrib.get("ContentType", "")
            if (
                not part_name.startswith("/")
                or not content_type
            ):
                raise UnsafeArchiveError("xlsx_parse_failed")
            try:
                canonical = _canonical_member_name(part_name[1:])
            except UnsafeArchiveError as exc:
                raise UnsafeArchiveError("xlsx_parse_failed") from exc
            if canonical in overrides:
                raise UnsafeArchiveError("xlsx_parse_failed")
            overrides[canonical] = content_type
        else:
            raise UnsafeArchiveError("xlsx_parse_failed")
    return defaults, overrides


def _content_type_for(
    part_name: str,
    defaults: dict[str, str],
    overrides: dict[str, str],
) -> str | None:
    if part_name in overrides:
        return overrides[part_name]
    suffix = PurePosixPath(part_name).suffix
    return defaults.get(suffix[1:].casefold()) if suffix else None


def _declared_worksheet_parts(
    xml_parts: dict[str, bytes],
) -> tuple[list[str], str | None]:
    defaults, overrides = _content_type_maps(
        _parse_xml_root(xml_parts, _CONTENT_TYPES_PART)
    )
    package_relationships = _relationship_records(
        _parse_xml_root(xml_parts, _PACKAGE_RELATIONSHIPS_PART)
    )
    office_documents = [
        record
        for record in package_relationships.values()
        if record[0] == _OFFICE_DOCUMENT_RELATIONSHIP
        and record[2] != "External"
    ]
    if len(office_documents) != 1:
        raise UnsafeArchiveError("xlsx_parse_failed")
    workbook_part = _resolve_relationship_target(
        "",
        office_documents[0][1],
    )
    if workbook_part != _WORKBOOK_PART:
        raise UnsafeArchiveError("xlsx_unsupported_layout")
    if (
        _content_type_for(workbook_part, defaults, overrides)
        != _WORKBOOK_CONTENT_TYPE
    ):
        raise UnsafeArchiveError("xlsx_unsupported_layout")

    workbook_root = _parse_xml_root(xml_parts, workbook_part)
    if workbook_root.tag != f"{{{_SPREADSHEET_NS}}}workbook":
        raise UnsafeArchiveError("xlsx_unsupported_layout")
    workbook_relationships = _relationship_records(
        _parse_xml_root(xml_parts, _WORKBOOK_RELATIONSHIPS_PART)
    )
    sheet_nodes = workbook_root.findall(
        f"./{{{_SPREADSHEET_NS}}}sheets/"
        f"{{{_SPREADSHEET_NS}}}sheet"
    )
    if not sheet_nodes:
        raise UnsafeArchiveError("xlsx_unsupported_layout")

    worksheet_parts: list[str] = []
    seen_parts: set[str] = set()
    relationship_id_attribute = f"{{{_OFFICE_RELATIONSHIPS_NS}}}id"
    for sheet in sheet_nodes:
        relationship_id = sheet.attrib.get(relationship_id_attribute, "")
        if not relationship_id or relationship_id not in workbook_relationships:
            raise UnsafeArchiveError("xlsx_parse_failed")
        relationship_type, target, target_mode = workbook_relationships[
            relationship_id
        ]
        if (
            relationship_type != _WORKSHEET_RELATIONSHIP
            or target_mode == "External"
        ):
            continue
        worksheet_part = _resolve_relationship_target(
            workbook_part,
            target,
        )
        if (
            not worksheet_part.startswith("xl/worksheets/")
            or _content_type_for(worksheet_part, defaults, overrides)
            != _WORKSHEET_CONTENT_TYPE
        ):
            raise UnsafeArchiveError("xlsx_unsupported_layout")
        if worksheet_part not in xml_parts:
            raise UnsafeArchiveError("xlsx_parse_failed")
        if worksheet_part in seen_parts:
            raise UnsafeArchiveError("xlsx_parse_failed")
        seen_parts.add(worksheet_part)
        worksheet_parts.append(worksheet_part)
    if not worksheet_parts:
        raise UnsafeArchiveError("xlsx_unsupported_layout")

    shared_string_parts = [
        _resolve_relationship_target(workbook_part, target)
        for relationship_type, target, target_mode
        in workbook_relationships.values()
        if relationship_type == _SHARED_STRINGS_RELATIONSHIP
        and target_mode != "External"
    ]
    if len(shared_string_parts) > 1:
        raise UnsafeArchiveError("xlsx_parse_failed")
    shared_string_part = (
        shared_string_parts[0] if shared_string_parts else None
    )
    if shared_string_part is not None:
        if (
            _content_type_for(shared_string_part, defaults, overrides)
            != _SHARED_STRINGS_CONTENT_TYPE
            or shared_string_part not in xml_parts
        ):
            raise UnsafeArchiveError("xlsx_parse_failed")
    return worksheet_parts, shared_string_part


def read_xlsx_table(
    path: Path,
    limits: ScanLimits,
) -> dict[str, list[list[str]]]:
    ns = {"a": _SPREADSHEET_NS}
    with zipfile.ZipFile(path) as archive:
        members = _validate_open_archive(archive, limits)
        xml_parts = _read_validated_members(archive, members, limits)

    worksheet_parts, shared_string_part = _declared_worksheet_parts(
        xml_parts
    )
    shared: list[str] | None = None
    if shared_string_part is not None:
        shared = []
        root = _parse_xml_root(xml_parts, shared_string_part)
        if root.tag != f"{{{_SPREADSHEET_NS}}}sst":
            raise UnsafeArchiveError("xlsx_parse_failed")
        for si in root.findall("a:si", ns):
            texts = [node.text or "" for node in si.findall(".//a:t", ns)]
            shared.append("".join(texts))

    sheets: dict[str, list[list[str]]] = {}
    for sheet_index, sheet_name in enumerate(worksheet_parts, 1):
        sheets[f"sheet{sheet_index}"] = _parse_worksheet(
            xml_parts[sheet_name],
            shared,
        )
    return sheets
