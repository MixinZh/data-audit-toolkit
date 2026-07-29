# Data Audit Toolkit

An offline toolkit for finding reproducible consistency leads across local tables, text, and images.

Data Audit Toolkit inventories the files you select, runs bounded deterministic checks, preserves hashes and evidence locations, and makes unsupported or skipped inputs visible. No account, upload, API key, or model is required.

## What it does

- Inventories selected local files with relative paths, sizes, and hashes.
- Checks supported tables, text, and images for reproducible consistency leads.
- Records unsupported, unavailable, ambiguous, or safety-bounded comparisons as `not_checked`.
- Writes a JSON report with evidence locations and separate observation, source, reviewer-inference, and not-checked layers.

## Quick start

### Use as a command-line tool

```bash
python3 -m pip install .
data-audit scan ./example-data --output ./audit-report.json
```

### Use as an Agent Skill

Install this directory as an Agent Skill, then follow `SKILL.md`: inventory the selected inputs, run the local scan command, inspect coverage and `not_checked` entries, and review any lead against the source files.

## Example result

```text
Files inventoried: 3
Files checked: 2
Consistency leads: 1
Not checked: 1
Report: audit-report.json
Review the report before drawing conclusions.
```

The report uses relative paths rather than absolute local paths:

```json
{
  "schema_version": "data-audit-v1",
  "inventory": [{"path": "example-data/values.csv", "status": "eligible"}],
  "finding_count": 1,
  "not_checked": [{"file": "example-data/report.pdf", "reason": "unsupported_file_type"}]
}
```

## Supported inputs

- Tables: `.csv`, `.tsv`, `.xlsx`
- Text: `.txt`, `.md`, `.html`, `.htm`
- Images: `.png`, `.jpg`, `.jpeg`, `.tif`, `.tiff`

Optional image checks require Pillow. Other file types are inventoried but not checked. See [`references/supported-inputs.md`](references/supported-inputs.md) for scan and resource limits.

## Privacy and boundaries

- Offline by default: the toolkit does not upload selected files.
- Deterministic checks: identical inputs and settings produce the same report.
- No telemetry is collected.
- Unsupported files are not checked and remain visible in the report.
- Optional image checks require Pillow.
- Leads require human review and are not final judgments.

## Testing

Run the complete test suite and the packaged synthetic benchmark:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_benchmark_suite.py
```

The benchmark contains 19 synthetic cases. It checks the packaged deterministic behavior, not a user's files.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for local development and contribution expectations. See [SECURITY.md](SECURITY.md) for vulnerability-reporting guidance.

## License

Licensed under the [Apache License 2.0](LICENSE).
