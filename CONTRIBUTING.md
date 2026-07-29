# Contributing

## Local setup

Use Python 3.10 or newer. Create a virtual environment, install the package in editable mode, and run the checks:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/check_benchmark_suite.py
```

## Contributions

Keep pull requests focused and include tests for changed behavior. Use synthetic fixtures only; do not add private, sensitive, or third-party source artifacts. Run the public-hygiene tests before opening a pull request:

```bash
PYTHONPATH=src .venv/bin/python -m unittest tests.test_public_hygiene -v
```

Describe output as reproducible observations or review leads. Keep source statements, reviewer inference, and not-checked material distinct. Findings require review and are not judgments about intent or responsibility.
