# Python Practices

Standards for all Python code in this repository.

---

## Logging

- Use the standard `logging` module. **Never use `print`.**
- Every module declares its own logger at module level:
  ```python
  import logging
  logger = logging.getLogger(__name__)
  ```
- The CLI entry point (`cli.py`) is the only place that configures handlers:
  ```python
  handler = logging.StreamHandler(sys.stderr)
  handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
  logging.getLogger().addHandler(handler)
  logging.getLogger().setLevel(logging.INFO)
  ```
- Verbose mode (`-v` / `--verbose`) sets the root logger to `DEBUG`.
- Log at the appropriate level: `DEBUG` for internal state, `INFO` for progress, `WARNING` for recoverable issues, `ERROR` for failures.

---

## Style

- **PEP 8**, enforced by `ruff`. Max line length: **100**.
- All public functions, methods, and classes carry **type annotations**.
- Docstrings on all public APIs using **Google style**:
  ```python
  def assess(target: str) -> RiskReport:
      """Assess the risk of an external FQDN or URL.

      Args:
          target: The FQDN or full URL to assess.

      Returns:
          A RiskReport with composite score and per-dimension findings.

      Raises:
          ValueError: If target is not a valid FQDN or URL.
      """
  ```

---

## Data Models

- Use **Pydantic v2** for all data structures that cross module boundaries.
- No raw `dict` as a function return type.
- Define models in `isrm/models.py` (shared) or alongside the module that owns them.

---

## Error Handling

- Raise **specific exceptions**, not bare `Exception`. Define domain exceptions in `isrm/exceptions.py` when needed.
- The CLI layer (`cli.py`) is the only place that catches top-level exceptions. It logs them and exits with a non-zero code. Stack traces are shown only in `--debug` mode.
- Collector failures (network errors, API errors) do not crash the pipeline. They return a `DATA_UNAVAILABLE` finding and log at `WARNING`.

---

## Testing

- **pytest**. Test files mirror the source layout under `tests/`:
  ```
  isrm/assess/collectors/dns.py  →  tests/assess/collectors/test_dns.py
  ```
- Mock all external calls (network, APIs, Claude SDK) in unit tests using `pytest-mock` or `unittest.mock`.
- Every collector and scorer module must have at least one unit test covering the happy path and one covering the `DATA_UNAVAILABLE` fallback.

---

## Dependencies

- Managed with **uv**. Never add a runtime or dev dependency without updating `pyproject.toml`.
- Pin the minimum required version, not an exact version, unless a specific version is required for a known reason.

---

## Project Commands

```bash
# Install all dependencies (including dev)
uv sync --all-extras

# Run tests
uv run pytest

# Run a single test
uv run pytest tests/assess/collectors/test_dns.py::test_resolve_a_record

# Lint
uv run ruff check .

# Type-check
uv run mypy isrm/

# Run the CLI
uv run isrm assess api.stripe.com
```
