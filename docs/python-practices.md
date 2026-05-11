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

> **Currently suspended** — do not run ruff or mypy during development. Speed and delivery take priority. Style enforcement and type-checking will be re-enabled at a later milestone.

Target conventions (enforced later):
- PEP 8, ruff, max line length 100.
- Type annotations on all public functions and classes.
- Google-style docstrings on public APIs.

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

> **Currently suspended** — do not write or run tests during development. Tests will be added at a later milestone once the core pipeline stabilizes.

Target conventions (enforced later):
- pytest, mirroring source layout under `tests/`.
- Mock all external calls (network, APIs, LLM SDK).

---

## Dependencies

- Managed with **uv**. Never add a runtime or dev dependency without updating `pyproject.toml`.

---

## Project Commands

```bash
# Install all dependencies
uv sync --all-extras

# Run the CLI
uv run isrm assess https://api.example.com
```
