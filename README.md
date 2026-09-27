# Data Audit Toolkit

**Check local files for inconsistencies without uploading them.**

Data Audit Toolkit is a free, experimental tool for checking spreadsheets, text
files, and images on your computer. It uses a set of rules to identify patterns
that may deserve a closer look before you use the data in your work.

No account, upload, API key, or AI model is required.

> **Coming soon:** A more powerful, easier-to-use agentic skill version is
> planned. It will build on the toolkit to help guide you through the audit
> process and interpret the results in plain language.

> **Important:** A result is a lead for a person to review, not proof that
> anything is wrong. Rounding, formatting, missing context, and other ordinary
> causes can produce similar patterns.

## What it can catch

The toolkit can flag patterns such as:

- the same numbers appearing under differently named columns
- a sample count stated one way in a methods section and another way in results
- a reported value that does not match the checked source table
- unusual repeated number patterns
- repeated regions within an image, when optional image support is installed

It also lists files it could not check because they were missing, unsupported,
unreadable, or blocked by a safety limit.

Each finding identifies the source file. Depending on the check, it may also
identify the relevant lines, rows, columns, or image regions. Some checks report
only the affected columns or summary counts.

## Quick start

The current release runs in a terminal.

### 1. Check the requirements

You need:

- [Python 3.10 or newer](https://www.python.org/downloads/)
- [Git](https://git-scm.com/downloads), or GitHub's **Download ZIP** option
- Linux or macOS. Windows is not currently supported.

Check your Python version:

```bash
python3 --version
```

If your computer uses `python` instead of `python3`, use `python` in the commands
below.

### 2. Download and install the toolkit

```bash
git clone https://github.com/MixinZh/data-audit-toolkit.git
cd data-audit-toolkit
python3 -m pip install .
```

If you do not use Git, select **Code → Download ZIP** near the top of this
GitHub page. Extract the downloaded file, then open your terminal in the
extracted folder and run:

```bash
python3 -m pip install .
```

### 3. Try the included example

```bash
data-audit scan examples/synthetic-case \
  --output audit-report.json
```

The terminal will show a short summary:

```text
Files inventoried: 3
Files checked: 2
Consistency leads: 5
Not checked: 1
Report: audit-report.json
Review the report before drawing conclusions.
```

- **Files inventoried**: every file the toolkit found.
- **Files checked**: files it was able to inspect.
- **Consistency leads**: patterns that can be reproduced and need human review.
- **Not checked**: files or comparisons the toolkit could not safely complete.
- **Report**: the detailed report saved on your computer.

To scan your own folder, replace the example path:

```bash
data-audit scan /path/to/your/files \
  --output audit-report.json
```

You can provide one file, one folder, or several file and folder paths.
The output report is automatically excluded from the current scan. Saving it
outside the scanned folder is still recommended to keep your source files
separate from generated reports.

Checks for inconsistent statistical wording use `0.05` as the default
significance threshold. Set a different threshold when your analysis requires
one:

```bash
data-audit scan /path/to/your/files \
  --output audit-report.json \
  --significance-alpha 0.01
```

## Supported files

| Type | File extensions | Notes |
| --- | --- | --- |
| Tables | `.csv`, `.tsv`, `.xlsx` | Included in the base installation |
| Text | `.txt`, `.md`, `.html`, `.htm` | Included in the base installation |
| Images | `.png`, `.jpg`, `.jpeg`, `.tif`, `.tiff` | Requires optional Pillow support |

To enable image checks, run this command from the toolkit folder:

```bash
python3 -m pip install ".[images]"
```

Other file types are listed in the report but are not inspected. PDF files are
not supported in this release. See
[supported inputs](references/supported-inputs.md) for the full list of limits.

## Privacy and limits

- Selected files stay on your computer. The toolkit does not upload them.
- No usage telemetry is collected.
- The toolkit reads the selected files and writes a separate report.
- Safety and size limits prevent unusually large or unsafe inputs from being
  opened.
- Unsupported or blocked files remain visible under `not_checked`.
- A file listed under `scanned_files` was read successfully. This does not mean
  that every claim or column was checked. Some checks require specific column
  names or data structures.
- Patterns involving final digits, unusually regular percentages, possible
  reverse calculations, and repeated image tiles are informational signals.
  They are not counted as consistency leads by default.
- Every lead needs human review, including a check for plausible ordinary
  explanations.

## What is in the report

The report is a JSON file, a structured text format that you can open in a text
editor or read with another program. It includes a file inventory, findings,
available source locations, and a list of anything that was not checked.

For example:

```json
{
  "finding_count": 1,
  "not_checked": [
    {
      "file": "example-data/report.pdf",
      "reason": "unsupported_file_type"
    }
  ]
}
```

See the [output schema](references/output-schema.md) for the full technical
format and the [signal map](references/signal-map.md) for an explanation of
the checks and their limits.

## Optional: use it with an AI agent

A basic Agent Skill is already included for compatible AI agents. You do not
need an agent to use the command-line tool.

Install this repository as an Agent Skill, then follow
[`SKILL.md`](SKILL.md). The skill instructs the agent to run the same local
scanner, explain what was and was not checked, and treat results as review
leads rather than final judgments.

The upcoming agentic skill version is intended to offer more capabilities
and a simpler, guided experience. Those improvements are planned and are not
part of the current release.

## For developers

### How it works: for technical readers

The scanner turns selected files into a JSON report of specific comparisons:
which values or statements disagree, where they came from, and what could not
be checked. The checks are Python rules, with no model inference or network
requests. The base package uses the Python standard library; Pillow is the
optional dependency for image checks.

```text
Selected files and folders
  -> inventory, SHA-256 hashes, temporary file snapshots
  -> format-specific parsing
  -> applicable table, text, and image checks
  -> findings, source locations, and not-checked reasons
  -> local JSON report
```

**1. Inventory the files and preserve the bytes being checked.**
[The traversal code](src/data_audit_toolkit/traversal.py) walks the selected
paths without following symlinks. It records relative paths, sizes, and
SHA-256 hashes for files it can safely read. Supported files are copied into
temporary snapshots during hashing, so the parser reads the bytes represented
by the recorded hash. A detected change during that read blocks the file.
The temporary snapshots are removed after the scan. Default intake limits are
1,000 files, 128 MiB per file, and 512 MiB total.

**2. Parse each supported file.**
[The scan engine](src/data_audit_toolkit/engine.py) reads UTF-8 CSV/TSV into
rows and passes text files, including HTML source, to the text checker. It
does not render HTML or run scripts. For XLSX,
[the workbook reader](src/data_audit_toolkit/archive.py) checks the ZIP
container and follows its declared workbook and worksheet relationships.
It reads stored cell values without recalculating formulas. Archive-size,
compression, XML, and worksheet limits can block parsing; the report records
the reason. Each worksheet is checked separately.

**3. Run the rules whose inputs are present.**
Checks run within a file or worksheet. The current scanner does not join
separate files, extract values from plotted figures, or automatically match a
paper's prose to a source workbook. Representative rules are:

| Check | What the code compares | Conditions and limits |
| --- | --- | --- |
| Numeric tables | Values in two columns for exact duplicates and fixed offsets; contiguous values within a column for repeated sequences | Missing cells keep their original row positions. Pairwise checks require at least two shared numeric rows and 80% overlap relative to the column with more numeric rows. Pair comparisons use at most 5,000 shared rows by default. |
| Reported means | The arithmetic mean of `value` rows grouped by `series_label`, compared with `reported_mean` | Each required column name must occur exactly once. The comparison allows for the reported number's displayed precision. |
| Counts and percentages | `100 * event_count / total_count`, compared with `displayed_percentage` | Requires those named fields and valid counts; allows for displayed precision. |
| Series in different panels | Values aligned by shared `index` values, grouped by `panel` and `series_label` | Requires different panel and series labels, unique indices within each series, and at least eight shared indices by default. Disclosed reuse can suppress the comparison. |
| Statistical wording | A written p-value and its inequality operator, paired with nearby significance wording in the same sentence or clause | Uses `--significance-alpha`, default `0.05`. It checks wording against the supplied value; it does not recompute the statistical test. |
| Methods/results statements | Explicit phrases such as `Methods sample count: n=12` and `Results sample count: n=10` | Uses text patterns for labeled statements, not general interpretation of unrestricted prose. |
| Repeated image tiles | Exact RGBA pixel bytes in non-overlapping tiles within one image | Requires Pillow; defaults to 32 by 32 pixel tiles and a four-million-pixel image limit. Reports the first repeated pair as informational. It does not match rotated, resized, or approximately similar regions. |

The implementations are in [table.py](src/data_audit_toolkit/checks/table.py),
[text.py](src/data_audit_toolkit/checks/text.py), and
[image.py](src/data_audit_toolkit/checks/image.py). Default thresholds are in
[ScanLimits](src/data_audit_toolkit/models.py). A parsed file may satisfy none
of a rule's prerequisites. The report does not yet provide a complete list of
rules applied to each file, and several rules retain only the first finding
of a given kind per table. Finding counts are not counts of every occurrence.

**Worked example: a reported mean.** Save this invented table as `means.csv`:

```csv
series_label,value,reported_mean
group_a,2,4.0
group_a,3,4.0
group_a,4,4.0
```

Run `data-audit scan means.csv --output means-report.json`. The checker groups
the three values under `group_a` and calculates `(2 + 3 + 4) / 3 = 3.0`.
The supplied mean is `4.0`; its one decimal place gives a rounding tolerance
of `0.05`. The difference exceeds that tolerance, so the report includes a
`reported_mean_mismatch` finding with this evidence:

```json
{
  "calculated_mean": 3.0,
  "reported_mean": 4.0,
  "series_label": "group_a",
  "tolerance": 0.05
}
```

This establishes a mismatch between the supplied values and the supplied
mean. A reviewer still needs to check whether the rows are complete, whether
the mean refers to another subset, or whether a transcription error occurred.

**4. Write a report that separates observations from interpretation.**
Each finding records its `kind`, source `path`, structured `evidence`,
`evidence_layer`, and `classification`. The evidence layer distinguishes a
computed comparison (`data_show`), supplied wording (`source_says`), a reviewer
inference, and material not checked. Classification distinguishes
`consistency_lead`, `informational`, and `not_checked`. These fields describe
the result; they are not confidence probabilities.

The engine sorts findings by path, kind, and evidence before
[the output writer](src/data_audit_toolkit/output.py) writes the report
atomically. It refuses to overwrite an existing report unless `--overwrite`
is supplied and rejects output paths that conflict with protected inputs.
`finding_count` includes all classifications; the terminal's **Consistency
leads** count includes only `consistency_lead` findings. A successful scan exits
`0` even when findings or unchecked files exist, so automation must inspect
the JSON rather than treating the exit code as a clean-data result.

For Python integration, the same scan is available through
`data_audit_toolkit.engine.scan_paths(inputs, limits=ScanLimits(...))`, which
returns the report dictionary. See the [output schema](references/output-schema.md)
for fields and reason codes, and [supported inputs](references/supported-inputs.md)
for parsing and resource limits.

### Test the implementation

Run the complete test suite and the included synthetic benchmark:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_benchmark_suite.py
```

The benchmark contains 19 synthetic cases. It checks whether the toolkit
behaves as expected on those examples. It does not validate a user's files
or measure real-world detection accuracy, precision, or recall.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and contribution
guidelines. See [SECURITY.md](SECURITY.md) for instructions on reporting
security vulnerabilities.

## License

Licensed under the [Apache License 2.0](LICENSE).
