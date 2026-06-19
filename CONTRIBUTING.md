# Contributing to mcp-shield

Thank you for your interest in making MCP security better! Here's how to contribute.

## Development Setup

```bash
git clone https://github.com/nousresearch/mcp-shield.git
cd mcp-shield
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
```

## Adding a New Detector

1. Create a new file in `src/mcp_shield/detectors/` (e.g., `my_detector.py`)
2. Implement the `BaseDetector` interface from `detectors/base.py`
3. Register it in the policy config and CLI
4. Add tests in `tests/test_detectors.py`
5. Update the README detector table

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Add or update tests for your changes
3. Ensure all tests pass: `pytest`
4. Open a PR with a clear description of what and why

## Reporting Security Issues

If you find a security vulnerability in mcp-shield itself, please **do not** open a public issue. Instead, email the maintainers directly. We'll respond within 48 hours.

## Code Style

- Python 3.10+
- Type hints on all public functions
- Docstrings on all public classes and methods
- Keep imports sorted (we don't enforce a formatter, but be consistent)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
