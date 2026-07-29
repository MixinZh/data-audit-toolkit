from __future__ import annotations

import itertools
import math
from collections import Counter, defaultdict
from typing import Any

from ..models import ScanLimits
from .common import (
    decimal_suffix,
    finding,
    numbers_equal,
    parse_number,
    terminal_digit,
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


def _column_values(
    headers: list[str],
    rows: list[list[str]],
) -> dict[str, list[str]]:
    return {
        header: [row[index].strip() for row in rows]
        for index, header in enumerate(headers)
    }


def _numeric_column(values: list[str]) -> list[float] | None:
    parsed = [parse_number(value) for value in values]
    if not values or any(value is None for value in parsed):
        return None
    return [value for value in parsed if value is not None]


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
    if not {"displayed_label", "source_label"}.issubset(headers):
        return
    displayed_index = headers.index("displayed_label")
    source_index = headers.index("source_label")
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
    if not {"series_label", "value", "reported_mean"}.issubset(headers):
        return
    label_index = headers.index("series_label")
    value_index = headers.index("value")
    mean_index = headers.index("reported_mean")
    grouped_values: dict[str, list[float]] = defaultdict(list)
    reported: dict[str, float] = {}
    for row in rows:
        value = parse_number(row[value_index])
        mean = parse_number(row[mean_index])
        label = row[label_index].strip()
        if label and value is not None:
            grouped_values[label].append(value)
        if label and mean is not None:
            reported[label] = mean
    for label in sorted(grouped_values):
        if label not in reported or not grouped_values[label]:
            continue
        calculated = sum(grouped_values[label]) / len(grouped_values[label])
        if not math.isfinite(calculated):
            continue
        if not numbers_equal(calculated, reported[label]):
            _add_once(
                findings,
                finding(
                    "reported_mean_mismatch",
                    path,
                    {
                        "calculated_mean": calculated,
                        "reported_mean": reported[label],
                        "series_label": label,
                        "tolerance": 1e-09,
                    },
                    evidence_layer="data_show",
                ),
            )


def _check_numeric_columns(
    path: str,
    columns: dict[str, list[str]],
    limits: ScanLimits,
    findings: list[dict[str, Any]],
) -> None:
    numeric = {
        label: values
        for label, raw_values in columns.items()
        if (values := _numeric_column(raw_values)) is not None
    }
    for (first_label, first), (second_label, second) in itertools.combinations(
        numeric.items(),
        2,
    ):
        pair_count = min(len(first), len(second), limits.max_pair_rows)
        if pair_count < 2:
            continue
        first_bounded = first[:pair_count]
        second_bounded = second[:pair_count]
        if first_bounded == second_bounded:
            _add_once(
                findings,
                finding(
                    "duplicate_numeric_columns",
                    path,
                    {
                        "columns": [first_label, second_label],
                        "row_count": pair_count,
                    },
                    evidence_layer="data_show",
                ),
            )

        raw_first = columns[first_label][:pair_count]
        raw_second = columns[second_label][:pair_count]
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
                        "columns": [first_label, second_label],
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
                        "columns": [first_label, second_label],
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
                            "columns": [first_label, second_label],
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
                            "columns": [first_label, second_label],
                            "dominant_ratio": dominant,
                            "outlier_count": len(material_outliers),
                        },
                        evidence_layer="data_show",
                    ),
                )

    for label, values in numeric.items():
        bounded = values[: limits.max_sequence_values]
        sequence_length = limits.min_sequence
        repeated = False
        if sequence_length > 0 and len(bounded) >= sequence_length * 2:
            for start in range(len(bounded) - sequence_length + 1):
                sequence = bounded[start : start + sequence_length]
                for second_start in range(start + sequence_length, len(bounded) - sequence_length + 1):
                    if sequence == bounded[second_start : second_start + sequence_length]:
                        repeated = True
                        break
                if repeated:
                    break
        if repeated:
            _add_once(
                findings,
                finding(
                    "repeated_numeric_sequence",
                    path,
                    {"column": label, "length": sequence_length},
                    evidence_layer="data_show",
                ),
            )

        if len(bounded) >= limits.min_n:
            terminal_digits = [
                digit
                for raw_value in columns[label][: len(bounded)]
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
                            "column": label,
                            "digit": digit,
                            "n": len(terminal_digits),
                            "observed": count,
                        },
                        evidence_layer="data_show",
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
                            "column": label,
                            "concentration": round(concentration, 6),
                            "n": len(terminal_digits),
                        },
                        evidence_layer="data_show",
                    ),
                )

        suffixes = [
            suffix
            for value in columns[label]
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
                        "column": label,
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
    if {"component_a", "component_b", "total"}.issubset(headers):
        indexes = [headers.index(name) for name in ("component_a", "component_b", "total")]
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
                ),
            )

    disclosure_index = (
        headers.index("formula_disclosed")
        if "formula_disclosed" in headers
        else None
    )
    if {"total_count", "displayed_percentage"}.issubset(headers):
        total_index = headers.index("total_count")
        percentage_index = headers.index("displayed_percentage")
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
                    ),
                )

    if {"total_count", "event_count", "displayed_percentage"}.issubset(headers):
        total_index = headers.index("total_count")
        event_index = headers.index("event_count")
        percentage_index = headers.index("displayed_percentage")
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
            if not numbers_equal(implied, percentage):
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
    required = {"panel", "series_label", "index", "value"}
    if not required.issubset(headers):
        return
    disclosure_index = (
        headers.index("reuse_disclosed")
        if "reuse_disclosed" in headers
        else None
    )
    panel_index = headers.index("panel")
    label_index = headers.index("series_label")
    order_index = headers.index("index")
    value_index = headers.index("value")
    grouped: dict[
        tuple[str, str],
        list[tuple[float, float, bool]],
    ] = defaultdict(list)
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
            grouped[key].append((order, value, disclosed))
    series = {
        key: [
            (value, disclosed)
            for _, value, disclosed in sorted(items)
        ]
        for key, items in grouped.items()
    }
    for (first_key, first), (second_key, second) in itertools.combinations(
        sorted(series.items()),
        2,
    ):
        if first_key[1] == second_key[1]:
            continue
        pair_count = min(len(first), len(second), limits.max_pair_rows)
        if pair_count < limits.min_sequence:
            continue
        first_pairs = first[:pair_count]
        second_pairs = second[:pair_count]
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
    )
    columns = _column_values(headers, data_rows)
    cross_panel_fields = {"panel", "series_label", "index", "value"}
    generic_numeric_columns = (
        {
            label: values
            for label, values in columns.items()
            if label not in {"index", "value"}
        }
        if cross_panel_fields.issubset(headers)
        else columns
    )
    _check_label_mapping(path, headers, data_rows, findings)
    _check_reported_means(path, headers, data_rows, findings)
    _check_numeric_columns(path, generic_numeric_columns, limits, findings)
    _check_named_calculations(path, headers, data_rows, findings)
    _check_cross_panel(path, headers, data_rows, limits, findings)
    return findings, not_checked
