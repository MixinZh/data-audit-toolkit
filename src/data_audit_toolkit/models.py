from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class ScanLimits:
    min_n: int = 20
    min_group_n: int = 8
    min_sequence: int = 8
    max_sequence_values: int = 5_000
    max_pair_rows: int = 5_000
    tile_size: int = 32
    max_files: int = 1_000
    max_total_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 128 * 1024 * 1024
    max_archive_entries: int = 1_000
    max_archive_uncompressed_bytes: int = 256 * 1024 * 1024
    max_archive_entry_bytes: int = 64 * 1024 * 1024
    max_archive_ratio: int = 100
    max_xml_bytes: int = 32 * 1024 * 1024


DEFAULT_LIMITS = ScanLimits()


@dataclass(frozen=True)
class InventoryEntry:
    absolute_path: Path
    relative_path: str
    size_bytes: int
    sha256: str | None
    status: Literal["eligible", "unsupported", "blocked"]
    reason: str | None


@dataclass(frozen=True)
class Inventory:
    entries: tuple[InventoryEntry, ...]
    input_roots: tuple[Path, ...]
