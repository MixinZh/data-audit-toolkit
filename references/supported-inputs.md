# Supported inputs and limits

The scan command accepts exact file paths or directories. It inventories regular
files without following symlinks and records a SHA-256 for eligible and
unsupported files.

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

## Resource boundaries

Default traversal limits are 1,000 files, 512 MiB total input bytes, and 128
MiB per file. XLSX containers are limited to 1,000 archive entries, 256 MiB
uncompressed archive bytes, 64 MiB per archive entry, a compression ratio of
100, and 32 MiB XML parts. Decoded images are limited to 4,000,000 pixels.

An unsupported entry means its type is outside this release. A blocked entry
means the tool stopped before checking it because of a safety, access, parsing,
or resource boundary. Neither state is evidence about the underlying content.
