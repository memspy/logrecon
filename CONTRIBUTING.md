# Contributing

Bug reports, parser formats, signature patterns and fixes are welcome.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
```

## Guidelines

- Keep changes focused and include tests. Parser formats need a sample line;
  signature patterns need at least one matching and one benign test case.
- New signatures must not match ordinary traffic. Check them against realistic
  benign lines before submitting.
- Code is kept free of comments and docstrings; make names and structure
  carry the meaning, and put explanations in the README.
- Do not add network access to the ingest service or publish its port.
- Run `python -m pytest -q` before opening a pull request.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
