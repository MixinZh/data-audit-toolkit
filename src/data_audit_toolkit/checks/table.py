from __future__ import annotations

import itertools
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from ..models import ScanLimits
from .common import (
    decimal_suffix,
    displayed_precision_tolerance,
    finding,
    numbers_equal,
    parse_number,
    terminal_digit,
    within_displayed_precision,
)
from .text import check_text


def _rectangular_rows(rows: list[list[str]]) -> tuple[list[str], list[list[str]]]:
    if not rows:
        return [], []
    width = max(len(row) for row in rows)
    normalized = [row + [""] * (width - len(row)) for row in rows]
    headers = [
        (value.strip() or f"column_{index + 1}")
        for index, value in enumerate(normalized[0])
    ]
    return headers, normalized[1:]


@dataclass(frozen=True)
class _Column:
    index: int
    label: str
    raw_values: tuple[str, ...]
    numeric_by_row: dict[int, float]


def _columns(
    headers: list[str],
    rows: list[list[str]],
) -> list[_Column]:
    columns: list[_Column] = []
    for index, header in enumerate(headers):
        raw_values = tuple(row[index].strip() for row in rows)
        numeric_by_row = {
            row_number: parsed
            for row_number, raw_value in enumerate(raw_values, 2)
            if (parsed := parse_number(raw_value)) is not None
        }
        columns.append(
            _Column(
                index=index,
                label=header,
                raw_values=raw_values,
                numeric_by_row=numeric_by_row,
            )
        )
    return columns


def _unique_header_index(headers: list[str], label: str) -> int | None:
    indexes = [
        index
        for index, header in enumerate(headers)
        if header == label
    ]
    return indexes[0] if len(indexes) == 1 else None


def _has_repeated_contiguous_sequence(
    column: _Column,
    *,
    sequence_length: int,
    max_values: int,
) -> bool:
    if sequence_length <= 0:
        return False
    bounded_rows = sorted(column.numeric_by_row)[:max_values]
    runs: list[list[float]] = []
    previous_row: int | None = None
    for row in bounded_rows:
        if previous_row is None or row != previous_row + 1:
            runs.append([])
        runs[-1].append(column.numeric_by_row[row])
        previous_row = row
    for values in runs:
        if len(values) < sequence_length * 2:
            continue
        for start in range(len(values) - sequence_length + 1):
            sequence = values[start : start + sequence_length]
            for second_start in range(
                start + sequence_length,
                len(values) - sequence_length + 1,
            ):
                if sequence == values[
                    second_start : second_start + sequence_length
                ]:
                    return True
    return False


def _add_once(
    findings: list[dict[str, Any]],
    candidate: dict[str, Any],
) -> None:
    if candidate["kind"] not in {item["kind"] for item in findings}:
        findings.append(candidate)


def _check_label_mapping(
    path: str,
    headers: list[str],
    rows: list[list[str]],
    findings: list[dict[str, Any]],
) -> None:
    displayed_index = _unique_header_index(headers, "displayed_label")
    source_index = _unique_header_index(headers, "source_label")
    if displayed_index is None or source_index is None:
        return
    for row_number, row in enumerate(rows, 2):
        displayed = row[displayed_index].strip()
        source = row[source_index].strip()
        if displayed and source and displayed != source:
            _add_once(
                findings,
                finding(
                    "label_mapping_mismatch",
                    path,
                    {
                        "displayed_label": displayed,
                        "row": row_number,
                        "source_label": source,
                    },
                    evidence_layer="data_show",
                ),
            )
            return


def _check_reported_means(
    path: str,
    headers: list[str],
    rows: list[list[str]],
    findings: list[dict[str, Any]],
) -> None:
    label_index = _unique_header_index(headers, "series_label")
    value_index = _unique_header_index(headers, "value")
    mean_index = _unique_header_index(headers, "reported_mean")
    if label_index is None or value_index is None or mean_index is None:
        return
    grouped_values: dict[str, list[float]] = defaultdict(list)
    reported: dict[str, tuple[float, str]] = {}
    for row in rows:
        value = parse_number(row[value_index])
        mean = parse_number(row[mean_index])
        label = row[label_index].strip()
        if label and value is not None:
            grouped_values[label].append(value)
        if label and mean is not None:
            reported[label] = (mean, row[mean_index].strip())
    for label in sorted(grouped_values):
        if label not in reported or not grouped_values[label]:
            continue
        calculated = sum(grouped_values[label]) / len(grouped_values[label])
        if not math.isfinite(calculated):
            continue
        reported_mean, reported_raw = reported[label]
        if not within_displayed_precision(calculated, reported_raw):
            tolerance = displayed_precision_tolerance(reported_raw)
            _add_once(
                findings,
                finding(
                    "reported_mean_mismatch",
                    path,
                    {
                        "calculated_mean": calculated,
                        "reported_mean": reported_mean,
                        "series_label": label,
                        "tolerance": tolerance,
                    },
                    evidence_layer="data_show",
                ),
            )


def _check_numeric_columns(
    path: str,
    columns: list[_Column],
    limits: ScanLimits,
    findings: list[dict[str, Any]],
) -> None:
    numeric = [
        column
        for column in columns
        if column.numeric_by_row
    ]
    for first, second in itertools.combinations(
        numeric,
        2,
    ):
        all_overlap_rows = sorted(
            set(first.numeric_by_row) & set(second.numeric_by_row)
        )
        required_overlap = max(
            2,
            math.ceil(
                max(
                    len(first.numeric_by_row),
                    len(second.numeric_by_row),
                )
                * limits.min_pair_overlap_ratio
            ),
        )
        if len(all_overlap_rows) < required_overlap:
            continue
        overlap_rows = all_overlap_rows[: limits.max_pair_rows]
        pair_count = len(overlap_rows)
        if pair_count < 2:
            continue
        first_bounded = [
            first.numeric_by_row[row]
            for row in overlap_rows
        ]
        second_bounded = [
            second.numeric_by_row[row]
            for row in overlap_rows
        ]
        pair_evidence = {
            "column_indices": [first.index + 1, second.index + 1],
            "columns": [first.label, second.label],
        }
        if first_bounded == second_bounded:
            _add_once(
                findings,
                finding(
                    "duplicate_numeric_columns",
                    path,
                    {
                        **pair_evidence,
                        "row_count": pair_count,
                        "rows": overlap_rows,
                    },
                    evidence_layer="data_show",
                ),
            )

        raw_first = [
            first.raw_values[row - 2]
            for row in overlap_rows
        ]
        raw_second = [
            second.raw_values[row - 2]
            for row in overlap_rows
        ]
        suffix_matches = sum(
            decimal_suffix(left) is not None
            and decimal_suffix(left) == decimal_suffix(right)
            for left, right in zip(raw_first, raw_second)
        )
        if (
            pair_count >= limits.min_group_n
            and suffix_matches == pair_count
            and first_bounded != second_bounded
        ):
            _add_once(
                findings,
                finding(
                    "paired_fractional_suffix_match",
                    path,
                    {
                        **pair_evidence,
                        "matching_rows": pair_count,
                    },
                    evidence_layer="data_show",
                ),
            )

        differences = [
            second_value - first_value
            for first_value, second_value in zip(first_bounded, second_bounded)
        ]
        if (
            pair_count >= 3
            and all(math.isfinite(value) for value in differences)
            and not numbers_equal(differences[0], 0.0)
            and all(numbers_equal(value, differences[0]) for value in differences)
        ):
            _add_once(
                findings,
                finding(
                    "fixed_difference_exact",
                    path,
                    {
                        **pair_evidence,
                        "difference": differences[0],
                        "row_count": pair_count,
                    },
                    evidence_layer="data_show",
                ),
            )

        if pair_count >= 4:
            first_shape = [
                first_bounded[index + 1] - first_bounded[index]
                for index in range(pair_count - 1)
            ]
            second_shape = [
                second_bounded[index + 1] - second_bounded[index]
                for index in range(pair_count - 1)
            ]
            if (
                first_bounded != second_bounded
                and all(math.isfinite(value) for value in first_shape)
                and all(math.isfinite(value) for value in second_shape)
                and all(
                    numbers_equal(left, right)
                    for left, right in zip(first_shape, second_shape)
                )
            ):
                _add_once(
                    findings,
                    finding(
                        "parallel_curve_shape",
                        path,
                        {
                            **pair_evidence,
                            "difference_count": len(first_shape),
                        },
                        evidence_layer="data_show",
                    ),
                )

        ratios = [
            right / left
            for left, right in zip(first_bounded, second_bounded)
            if not numbers_equal(left, 0.0)
            and math.isfinite(right / left)
        ]
        if len(ratios) >= 4:
            rounded = [round(value, 9) for value in ratios]
            dominant, dominant_count = Counter(rounded).most_common(1)[0]
            material_outliers = [
                value
                for value in ratios
                if abs(value - dominant) > max(abs(dominant) * 0.05, 0.05)
            ]
            if (
                dominant_count >= len(rounded) - 1
                and dominant_count < len(rounded)
                and material_outliers
            ):
                _add_once(
                    findings,
                    finding(
                        "ratio_consistency_outliers",
                        path,
                        {
                            **pair_evidence,
                            "dominant_ratio": dominant,
                            "outlier_count": len(material_outliers),
                        },
                        evidence_layer="data_show",
                    ),
                )

    for column in numeric:
        bounded_rows = sorted(column.numeric_by_row)[
            : limits.max_sequence_values
        ]
        bounded = [
            column.numeric_by_row[row]
            for row in bounded_rows
        ]
        sequence_length = limits.min_sequence
        if _has_repeated_contiguous_sequence(
            column,
            sequence_length=sequence_length,
            max_values=limits.max_sequence_values,
        ):
            _add_once(
                findings,
                finding(
                    "repeated_numeric_sequence",
                    path,
                    {"column": column.label, "length": sequence_length},
                    evidence_layer="data_show",
                ),
            )

        if len(bounded) >= limits.min_n:
            terminal_digits = [
                digit
                for raw_value in (
                    column.raw_values[row - 2]
                    for row in bounded_rows
                )
                if (digit := terminal_digit(raw_value)) is not None
            ]
            if len(terminal_digits) < limits.min_n:
                continue
            counts = Counter(terminal_digits)
            digit, count = counts.most_common(1)[0]
            if count / len(terminal_digits) >= 0.8:
                _add_once(
                    findings,
                    finding(
                        "terminal_digit_spike",
                        path,
                        {
                            "column": column.label,
                            "digit": digit,
                            "n": len(terminal_digits),
                            "observed": count,
                        },
                        evidence_layer="data_show",
                        classification="informational",
                    ),
                )
            concentration = sum(
                (frequency / len(terminal_digits)) ** 2
                for frequency in counts.values()
            )
            if concentration >= 0.5:
                _add_once(
                    findings,
                    finding(
                        "terminal_digit_distribution",
                        path,
                        {
                            "column": column.label,
                            "concentration": round(concentration, 6),
                            "n": len(terminal_digits),
                        },
                        evidence_layer="data_show",
                        classification="informational",
                    ),
                )

        suffixes = [
            suffix
            for value in column.raw_values
            if (suffix := decimal_suffix(value)) is not None
        ]
        if (
            len(suffixes) >= limits.min_group_n
            and len(set(suffixes)) == 1
            and suffixes[0] != "0"
        ):
            _add_once(
                findings,
                finding(
                    "group_decimal_suffix_uniformity",
                    path,
                    {
                        "column": column.label,
                        "row_count": len(suffixes),
                        "suffix": suffixes[0],
                    },
                    evidence_layer="data_show",
                ),
            )


def _check_named_calculations(
    path: str,
    headers: list[str],
    rows: list[list[str]],
    findings: list[dict[str, Any]],
) -> None:
    component_indexes = [
        _unique_header_index(headers, name)
        for name in ("component_a", "component_b", "total")
    ]
    if all(index is not None for index in component_indexes):
        indexes = [
            index
            for index in component_indexes
            if index is not None
        ]
        valid_rows = 0
        for row in rows:
            values = [parse_number(row[index]) for index in indexes]
            if all(value is not None for value in values):
                first, second, total = values
                reconstructed = first + second
                if math.isfinite(reconstructed) and numbers_equal(reconstructed, total):
                    valid_rows += 1
        if valid_rows >= 2:
            _add_once(
                findings,
                finding(
                    "reverse_calculation_chain",
                    path,
                    {"reconstructed_rows": valid_rows},
                    evidence_layer="data_show",
                    classification="informational",
                ),
            )

    disclosure_index = _unique_header_index(headers, "formula_disclosed")
    total_index = _unique_header_index(headers, "total_count")
    percentage_index = _unique_header_index(headers, "displayed_percentage")
    if total_index is not None and percentage_index is not None:
        qualifying: list[tuple[int, float]] = []
        for row in rows:
            if (
                disclosure_index is not None
                and row[disclosure_index].strip().casefold() in {"yes", "true", "disclosed"}
            ):
                continue
            total = parse_number(row[total_index])
            percentage = parse_number(row[percentage_index])
            if (
                total is not None
                and percentage is not None
                and total.is_integer()
                and 1 <= total <= 100
            ):
                qualifying.append((int(total), percentage))
        if len(qualifying) >= 2 and len({item[0] for item in qualifying}) == 1:
            total = qualifying[0][0]
            increment = 100.0 / total
            if all(
                numbers_equal(percentage / increment, round(percentage / increment))
                for _, percentage in qualifying
            ):
                _add_once(
                    findings,
                    finding(
                        "percentage_quantization_constraint",
                        path,
                        {
                            "display_increment": increment,
                            "row_count": len(qualifying),
                            "total_count": total,
                        },
                        evidence_layer="data_show",
                        classification="informational",
                    ),
                )

    event_index = _unique_header_index(headers, "event_count")
    if (
        total_index is not None
        and event_index is not None
        and percentage_index is not None
    ):
        for row_number, row in enumerate(rows, 2):
            if (
                disclosure_index is not None
                and row[disclosure_index].strip().casefold() in {"yes", "true", "disclosed"}
            ):
                continue
            total = parse_number(row[total_index])
            event_count = parse_number(row[event_index])
            percentage = parse_number(row[percentage_index])
            if (
                total is None
                or event_count is None
                or percentage is None
                or not total.is_integer()
                or not event_count.is_integer()
                or total <= 0
            ):
                continue
            implied = event_count / total * 100.0
            if not math.isfinite(implied):
                continue
            displayed_raw = row[percentage_index].strip()
            if not within_displayed_precision(implied, displayed_raw):
                _add_once(
                    findings,
                    finding(
                        "allegation_count_impossible",
                        path,
                        {
                            "displayed_percentage": percentage,
                            "event_count": int(event_count),
                            "implied_percentage": implied,
                            "row": row_number,
                            "tolerance": displayed_precision_tolerance(
                                displayed_raw
                            ),
                            "total_count": int(total),
                        },
                        evidence_layer="data_show",
                    ),
                )
                return


def _check_cross_panel(
    path: str,
    headers: list[str],
    rows: list[list[str]],
    limits: ScanLimits,
    findings: list[dict[str, Any]],
) -> None:
    panel_index = _unique_header_index(headers, "panel")
    label_index = _unique_header_index(headers, "series_label")
    order_index = _unique_header_index(headers, "index")
    value_index = _unique_header_index(headers, "value")
    if any(
        index is None
        for index in (panel_index, label_index, order_index, value_index)
    ):
        return
    assert panel_index is not None
    assert label_index is not None
    assert order_index is not None
    assert value_index is not None
    disclosure_index = _unique_header_index(headers, "reuse_disclosed")
    grouped: dict[
        tuple[str, str],
        dict[float, tuple[float, bool]],
    ] = defaultdict(dict)
    duplicate_index_groups: set[tuple[str, str]] = set()
    for row in rows:
        order = parse_number(row[order_index])
        value = parse_number(row[value_index])
        key = (row[panel_index].strip(), row[label_index].strip())
        if key[0] and key[1] and order is not None and value is not None:
            disclosed = (
                disclosure_index is not None
                and row[disclosure_index].strip().casefold()
                in {"yes", "true", "disclosed"}
            )
            if order in grouped[key]:
                duplicate_index_groups.add(key)
                continue
            grouped[key][order] = (value, disclosed)
    series = {
        key: items
        for key, items in grouped.items()
        if key not in duplicate_index_groups
    }
    for (first_key, first), (second_key, second) in itertools.combinations(
        sorted(series.items()),
        2,
    ):
        if first_key[0] == second_key[0] or first_key[1] == second_key[1]:
            continue
        matching_indexes = sorted(set(first) & set(second))[
            : limits.max_pair_rows
        ]
        pair_count = len(matching_indexes)
        if pair_count < limits.min_sequence:
            continue
        first_pairs = [first[index] for index in matching_indexes]
        second_pairs = [second[index] for index in matching_indexes]
        if all(
            first_disclosed or second_disclosed
            for (_, first_disclosed), (_, second_disclosed)
            in zip(first_pairs, second_pairs)
        ):
            continue
        first_bounded = [value for value, _ in first_pairs]
        second_bounded = [value for value, _ in second_pairs]
        evidence = {
            "first_series": first_key[1],
            "length": pair_count,
            "second_series": second_key[1],
        }
        if first_bounded == second_bounded:
            _add_once(
                findings,
                finding(
                    "cross_panel_exact_reuse",
                    path,
                    evidence,
                    evidence_layer="data_show",
                ),
            )
            continue
        offsets = [
            right - left
            for left, right in zip(first_bounded, second_bounded)
        ]
        if (
            all(math.isfinite(offset) for offset in offsets)
            and not numbers_equal(offsets[0], 0.0)
            and all(numbers_equal(offset, offsets[0]) for offset in offsets)
        ):
            _add_once(
                findings,
                finding(
                    "cross_panel_fixed_offset_chain",
                    path,
                    {**evidence, "offset": offsets[0]},
                    evidence_layer="data_show",
                ),
            )


def check_table(
    rows: list[list[str]],
    path: str,
    limits: ScanLimits,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    headers, data_rows = _rectangular_rows(rows)
    if not headers:
        return [], []
    findings, not_checked = check_text(
        "\n".join("\t".join(row) for row in rows),
        path,
        significance_alpha=limits.significance_alpha,
    )
    columns = _columns(headers, data_rows)
    cross_panel_fields = {"panel", "series_label", "index", "value"}
    generic_numeric_columns = (
        [
            column
            for column in columns
            if column.label not in {"index", "value"}
        ]
        if cross_panel_fields.issubset(headers)
        else columns
    )
    _check_label_mapping(path, headers, data_rows, findings)
    _check_reported_means(path, headers, data_rows, findings)
    _check_numeric_columns(path, generic_numeric_columns, limits, findings)
    _check_named_calculations(path, headers, data_rows, findings)
    _check_cross_panel(path, headers, data_rows, limits, findings)
    return findings, not_checked
