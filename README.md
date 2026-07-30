# Data Audit Toolkit

**Check local files for inconsistencies — without uploading them.**

Data Audit Toolkit is a free command-line tool that scans spreadsheets, text
files, and images on your computer. It points you to patterns that may deserve a
closer look and tells you which files it could not inspect.

No account, upload, API key, or AI model is required.

> **Important:** A result is a lead for a person to review, not proof that
> anything is wrong. Rounding, formatting, missing context, and other ordinary
> causes can produce similar patterns.

## What it can catch

The toolkit can flag examples such as:

- the same numbers appearing under differently named columns
- a sample count stated one way in a methods section and another way in results
- a reported value that does not match the checked source table
- unusual repeated number patterns
- repeated regions inside an image, when optional image support is installed
- files that were missing, unsupported, unreadable, or stopped by a safety limit

The report shows the source file and relevant cells, rows, or lines for each
lead. The same files and settings produce the same result, so another reviewer
can repeat the check.

## Quick start

The current release uses a terminal rather than a graphical app.

### 1. Check the requirements

You need:

- [Python 3.10 or newer](https://www.python.org/downloads/)
- [Git](https://git-scm.com/downloads), or GitHub's **Download ZIP** option

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
GitHub page, extract the downloaded file, and open your terminal in that folder
before running the install command.

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
- **Consistency leads**: reproducible patterns for a person to review.
- **Not checked**: files or comparisons the toolkit could not safely complete.
- **Report**: the detailed report saved on your computer.

To scan your own folder, replace the example path:

```bash
data-audit scan /path/to/your/files \
  --output audit-report.json
```

The input can be one file, one folder, or several file and folder paths. The
output report must be saved outside the folder being scanned.

## Supported files

| Type | File extensions | Notes |
| --- | --- | --- |
| Tables | `.csv`, `.tsv`, `.xlsx` | Included in the base install |
| Text | `.txt`, `.md`, `.html`, `.htm` | Included in the base install |
| Images | `.png`, `.jpg`, `.jpeg`, `.tif`, `.tiff` | Requires optional Pillow support |

To enable image checks:

```bash
python3 -m pip install ".[images]"
```

Other file types are listed in the report but are not inspected. PDF files are
not supported in this release. See
[`references/supported-inputs.md`](references/supported-inputs.md) for the full
list of limits.

## Privacy and limits

- Selected files stay on your computer; the toolkit does not upload them.
- No telemetry is collected.
- The toolkit reads the selected inputs and writes a separate report.
- Safety and size limits stop unusually large or unsafe inputs from being
  opened.
- Unsupported or blocked files remain visible under `not_checked`.
- Every lead needs human review and a check of plausible ordinary explanations.

## What is in the report

The report is a JSON file, a structured text format that can be opened in a text
editor or used by another program. It includes an inventory, findings, source
locations, and a visible list of anything not checked.

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

See [`references/output-schema.md`](references/output-schema.md) for the full
technical format and [`references/signal-map.md`](references/signal-map.md) for
the checks and interpretation boundaries.

## Optional: use it as an Agent Skill

This section is only for people using a compatible AI agent. You do not need an
agent to use the command-line tool.

Install this repository as an Agent Skill, then follow
[`SKILL.md`](SKILL.md). The skill instructs the agent to run the same local
scanner, show what was and was not checked, and treat results as review leads
rather than final judgments.

## For developers

Run the complete test suite and the packaged synthetic benchmark:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_benchmark_suite.py
```

The benchmark contains 19 synthetic cases. It checks the packaged behavior, not
a user's files.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for local development and contribution
expectations. See [SECURITY.md](SECURITY.md) for vulnerability-reporting
guidance.

## License

Licensed under the [Apache License 2.0](LICENSE).
