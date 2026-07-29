# Output schema

Every scan writes JSON with `schema_version` set to `data-audit-v1`.

## Top-level fields

- `findings`: ordered reproducible review leads.
- `finding_count`: total number of findings across all classifications.
- `counts_by_kind`: finding counts keyed by kind.
- `inventory`: every discovered input entry.
- `scanned_files`: eligible files successfully checked.
- `unsupported_files`: inventoried files whose type is unsupported.
- `blocked_files`: files that could not be checked safely or completely.
- `not_checked`: explicit unavailable, unsupported, ambiguous, or blocked
  comparisons.
- `evidence_layer_definitions`: meanings for `data_show`, `source_says`,
  `reviewer_inference`, and `not_checked`.
- `verdict_boundary`: the rule that findings are not final judgments.

Each inventory entry contains `path`, `size_bytes`, `sha256`, `status`
(`eligible`, `unsupported`, or `blocked`), and `reason` (or `null`).

Each finding contains `kind`, `path`, `evidence_layer`, `classification`,
`verdict_boundary`, and structured `evidence`. Use the evidence layer rather
than inferring certainty from a finding kind. Findings can be informational,
not checked, or consistency leads; they are not misconduct conclusions.
The command-line `Consistency leads` summary counts only findings whose
`classification` is `consistency_lead`; it does not reuse `finding_count`.

## Stable reason codes and exits

Common `not_checked` or inventory reasons include
`unsupported_file_type`, `image_dependency_unavailable`,
`image_resource_limit_exceeded`, `image_parse_failed`, `text_parse_failed`,
`table_parse_failed`, `xlsx_parse_failed`, `file_parse_failed`,
`file_read_failed`, `file_changed_during_inventory`, `snapshot_unavailable`,
`filesystem_access_failed`, `symlink_not_followed`, `special_file_blocked`,
`max_files_exceeded`, `max_total_bytes_exceeded`, `max_file_bytes_exceeded`,
`archive_path_traversal`, `archive_duplicate_entry`, `archive_encrypted_entry`,
`archive_entries_exceeded`, `archive_entry_bytes_exceeded`,
`archive_uncompressed_bytes_exceeded`, `archive_ratio_exceeded`,
`archive_unsupported_compression`, `archive_entry_size_mismatch`,
`xml_bytes_exceeded`, `worksheet_dimensions_exceeded`, and
`xlsx_unsupported_layout`.

`scan` exits 0 after writing a report; handled output errors and operational
failures exit 1; invalid command-line syntax exits 2. The benchmark wrapper
exits 0 when `failures` is empty and 1 otherwise.
