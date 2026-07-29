from __future__ import annotations

import csv
import io
import json
import os
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter
from collections.abc import Collection, Sequence
from pathlib import Path
from typing import Any

from .archive import UnsafeArchiveError, read_xlsx_table
from .checks import check_image, check_table, check_text
from .models import DEFAULT_LIMITS, InventoryEntry, ScanLimits
from .traversal import _collect_inputs_with_snapshots


_TEXT_SUFFIXES = frozenset({".txt", ".md", ".html", ".htm"})
_TABLE_SUFFIXES = frozenset({".csv", ".tsv"})
_IMAGE_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".tif", ".tiff"})
_SUPPORTED_SUFFIXES = (
    _TEXT_SUFFIXES
    | _TABLE_SUFFIXES
    | _IMAGE_SUFFIXES
    | frozenset({".xlsx"})
)
_VERDICT_BOUNDARY = (
    "Findings are reproducible consistency leads for human review, "
    "not final judgments."
)
_EVIDENCE_LAYER_DEFINITIONS = {
    "data_show": "Directly reproducible structure or value comparison.",
    "source_says": "A literal statement supplied in the scanned files.",
    "reviewer_inference": "A bounded consistency lead requiring review.",
    "not_checked": "An unsupported or unavailable comparison.",
}


def _inventory_item(
    entry: InventoryEntry,
    parse_reason: str | None,
) -> dict[str, Any]:
    status = "blocked" if parse_reason is not None else entry.status
    reason = parse_reason if parse_reason is not None else entry.reason
    return {
        "path": entry.relative_path,
        "size_bytes": entry.size_bytes,
        "sha256": entry.sha256,
        "status": status,
        "reason": reason,
    }


def _blocked_not_checked(path: str, reason: str) -> dict[str, Any]:
    archive_reason = reason.startswith("archive_") or reason in {
        "xml_bytes_exceeded",
        "worksheet_dimensions_exceeded",
    }
    return {
        "file": path,
        "reason": reason,
        "meaning": (
            "This container was inventoried but not checked because it "
            "exceeded a safety boundary."
            if archive_reason
            else "This file was inventoried but could not be checked."
        ),
    }


def _unsupported_not_checked(path: str, reason: str) -> dict[str, Any]:
    return {
        "file": path,
        "reason": reason,
        "classification": "not_checked",
        "meaning": (
            "This file type was inventoried but is not supported by this release."
        ),
    }


def _decode_utf8(source: Path) -> str:
    return source.read_bytes().decode("utf-8")


def _read_delimited(source: Path, suffix: str) -> list[list[str]]:
    text = _decode_utf8(source)
    delimiter = "\t" if suffix == ".tsv" else ","
    return list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter))


def _scan_snapshot(
    source: Path,
    public_path: str,
    suffix: str,
    limits: ScanLimits,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None]:
    try:
        if suffix in _TEXT_SUFFIXES:
            findings, not_checked = check_text(_decode_utf8(source), public_path)
            return findings, not_checked, None
        if suffix in _TABLE_SUFFIXES:
            findings, not_checked = check_table(
                _read_delimited(source, suffix),
                public_path,
                limits,
            )
            return findings, not_checked, None
        if suffix == ".xlsx":
            findings: list[dict[str, Any]] = []
            not_checked: list[dict[str, Any]] = []
            for sheet_name, rows in sorted(read_xlsx_table(source, limits).items()):
                sheet_findings, sheet_not_checked = check_table(
                    rows,
                    public_path,
                    limits,
                )
                for item in sheet_findings:
                    item["evidence"] = {
                        **item["evidence"],
                        "sheet": sheet_name,
                    }
                findings.extend(sheet_findings)
                not_checked.extend(sheet_not_checked)
            return findings, not_checked, None
        if suffix in _IMAGE_SUFFIXES:
            findings, reason = check_image(source, public_path, limits)
            return findings, [], reason
    except UnicodeDecodeError:
        return [], [], (
            "table_parse_failed"
            if suffix in _TABLE_SUFFIXES
            else "text_parse_failed"
        )
    except UnsafeArchiveError as exc:
        return [], [], exc.reason
    except ET.ParseError:
        return [], [], "xlsx_parse_failed"
    except (csv.Error, json.JSONDecodeError):
        return [], [], "table_parse_failed"
    except (OSError, ValueError, zipfile.BadZipFile):
        return [], [], (
            "xlsx_parse_failed"
            if suffix == ".xlsx"
            else "file_parse_failed"
        )
    return [], [], "unsupported_file_type"


def _expanded_exclusions(
    inputs: Sequence[str | Path],
    excluded_paths: Collection[Path],
) -> tuple[Path, ...]:
    input_aliases = [
        (
            Path(os.path.abspath(os.fspath(Path(item).expanduser()))),
            Path(item).expanduser().resolve(strict=False),
        )
        for item in inputs
    ]
    expanded: set[Path] = set()
    for excluded in excluded_paths:
        lexical = Path(
            os.path.abspath(os.fspath(Path(excluded).expanduser()))
        )
        resolved = Path(excluded).expanduser().resolve(strict=False)
        expanded.update({lexical, resolved})
        for input_lexical, input_resolved in input_aliases:
            try:
                relative = resolved.relative_to(input_resolved)
            except ValueError:
                continue
            expanded.add(input_lexical / relative)
    return tuple(sorted(expanded, key=os.fspath))


def scan_paths(
    inputs: Sequence[str | Path],
    *,
    limits: ScanLimits = DEFAULT_LIMITS,
    excluded_paths: Collection[Path] = (),
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scanned_files: list[str] = []
    unsupported_files: list[str] = []
    blocked_files: list[str] = []
    not_checked: list[dict[str, Any]] = []
    parse_reasons: dict[str, str] = {}

    with _collect_inputs_with_snapshots(
        inputs,
        limits=limits,
        excluded_paths=_expanded_exclusions(inputs, excluded_paths),
        supported_suffixes=_SUPPORTED_SUFFIXES,
    ) as (inventory, snapshots):
        for entry in inventory.entries:
            public_path = entry.relative_path
            if entry.status == "unsupported":
                unsupported_files.append(public_path)
                not_checked.append(
                    _unsupported_not_checked(
                        public_path,
                        entry.reason or "unsupported_file_type",
                    )
                )
                continue
            if entry.status == "blocked":
                blocked_files.append(public_path)
                not_checked.append(
                    _blocked_not_checked(
                        public_path,
                        entry.reason or "file_read_failed",
                    )
                )
                continue
            snapshot = snapshots.get(public_path)
            if snapshot is None:
                reason = "snapshot_unavailable"
                parse_reasons[public_path] = reason
                blocked_files.append(public_path)
                not_checked.append(_blocked_not_checked(public_path, reason))
                continue
            suffix = entry.absolute_path.suffix.casefold()
            file_findings, file_not_checked, parse_reason = _scan_snapshot(
                snapshot,
                public_path,
                suffix,
                limits,
            )
            findings.extend(file_findings)
            not_checked.extend(file_not_checked)
            if parse_reason is None:
                scanned_files.append(public_path)
            else:
                parse_reasons[public_path] = parse_reason
                blocked_files.append(public_path)
                not_checked.append(
                    _blocked_not_checked(public_path, parse_reason)
                )

        public_inventory = [
            _inventory_item(entry, parse_reasons.get(entry.relative_path))
            for entry in inventory.entries
        ]

    findings.sort(
        key=lambda item: (
            item["path"],
            item["kind"],
            json.dumps(item["evidence"], sort_keys=True),
        )
    )
    counts_by_kind = dict(
        sorted(Counter(item["kind"] for item in findings).items())
    )
    return {
        "schema_version": "data-audit-v1",
        "findings": findings,
        "finding_count": len(findings),
        "counts_by_kind": counts_by_kind,
        "inventory": public_inventory,
        "scanned_files": scanned_files,
        "unsupported_files": unsupported_files,
        "blocked_files": blocked_files,
        "not_checked": not_checked,
        "evidence_layer_definitions": _EVIDENCE_LAYER_DEFINITIONS,
        "verdict_boundary": _VERDICT_BOUNDARY,
    }
