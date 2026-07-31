# Supported inputs and limits

The scan command accepts exact file paths or directories. It inventories regular
files without following symlinks and records a SHA-256 for eligible and
unsupported files.

## Supported platforms

The secure traversal and atomic-output implementation currently supports Linux
and macOS. Windows is not supported by this release and may fail closed because
the required directory-descriptor operations are unavailable.

## Supported scan formats

- Tables: `.csv`, `.tsv`, `.xlsx`
- Text: `.txt`, `.md`, `.html`, `.htm`
- Images: `.png`, `.jpg`, `.jpeg`, `.tif`, `.tiff`

XLSX support follows the package's declared workbook and worksheet
relationships. Empty ZIP files, arbitrary ZIP files renamed to `.xlsx`,
incomplete workbook packages, orphan worksheet XML, and packages with no
supported declared worksheet are blocked and reported as not checked.

Image checks require the optional Pillow dependency. Without it, image files
remain inventoried and are recorded as not checked with
`image_dependency_unavailable`. Other extensions, including PDFs and archive
files, are inventoried but not checked with `unsupported_file_type`.

## Semantic applicability

Parsing support and semantic coverage are different. A file in `scanned_files`
was parsed, but only applicable rules were run.

- Generic numeric-column rules can compare numeric CSV, TSV, and worksheet
  columns. Duplicate header labels retain separate column identities.
- Reported-mean, count/percentage, label-mapping, and cross-panel rules require
  their documented field names, such as `series_label`, `value`,
  `reported_mean`, `total_count`, `event_count`, `displayed_percentage`,
  `panel`, and `index`.
- Missing numeric cells are masked. Pairwise rules require at least 80% overlap
  across the numeric rows of the larger column.
- Cross-panel comparison requires different panels, unique index values, and
  enough shared index values. Values are never aligned only by sorted position.
- Statistical-language checks pair each p-value with wording in its local
  sentence or clause, preserve `<`, `>`, `<=`, `>=`, or `=`, and use the
  configured significance alpha.
- Methods/results test and sample-count checks currently recognize explicit
  labeled phrases rather than unrestricted prose.

If a parsed file does not match a rule's prerequisites, that rule makes no claim
about the file. This release does not yet expose a complete per-file
`checks_applied` applicability ledger.

## Resource boundaries

Default traversal limits are 1,000 files, 512 MiB total input bytes, and 128
MiB per file. XLSX containers are limited to 1,000 archive entries, 256 MiB
uncompressed archive bytes, 64 MiB per archive entry, a compression ratio of
100, and 32 MiB XML parts. Decoded images are limited to 4,000,000 pixels.

An unsupported entry means its type is outside this release. A blocked entry
means the tool stopped before checking it because of a safety, access, parsing,
or resource boundary. Neither state is evidence about the underlying content.
