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
