# Repository Guidelines

## Project Structure & Module Organization

This repository is a HACS-compatible Home Assistant custom integration. Runtime
code lives in `custom_components/pfsense/`: `__init__.py` handles integration
setup and shared data, while `sensor.py`, `binary_sensor.py`, `switch.py`,
`device_tracker.py`, and `update.py` implement platforms. The bundled XML-RPC
client is in `custom_components/pfsense/pypfsense/`. Keep service definitions,
translations, and integration metadata in `services.yaml`, `translations/`, and
`manifest.json`. Tests live in `tests/` and generally mirror runtime modules.
GitHub Actions workflows under `.github/workflows/` define the canonical checks.

## Build, Test, and Development Commands

There is no compilation step or standalone development server. Create an
isolated environment and install the pinned tooling:

```bash
uv venv
source .venv/bin/activate
uv pip install -r requirements_dev.txt
```

Run the same checks as CI before opening a pull request:

```bash
python -m pytest
ruff check custom_components tests
black --check custom_components tests
isort --check-only custom_components tests
```

For manual end-to-end testing, install the integration through HACS or copy
`custom_components/pfsense` into a Home Assistant configuration, then restart
Home Assistant.

## Coding Style & Naming Conventions

Use four-space indentation and Black formatting; `pyproject.toml` targets Python
3.13 and configures isort with the Black profile. Use `snake_case` for modules,
functions, and variables, `PascalCase` for classes, and `UPPER_SNAKE_CASE` for
constants. Follow Home Assistant async conventions, and run blocking XML-RPC
work through `hass.async_add_executor_job`. Add comments only when they explain
non-obvious intent.

## Testing Guidelines

Use pytest and pytest-asyncio. Name files `test_<module>.py` and functions
`test_<behavior>()`; mark async tests with `@pytest.mark.asyncio`. Prefer
`Mock`/`AsyncMock` fixtures over live pfSense access. Run a focused file first,
for example `python -m pytest tests/test_services.py`, then the full suite.
There is no configured coverage threshold, but every regression should include
a targeted test.

## Security, Commits, and Pull Requests

Never commit or log credentials. Preserve SSL verification defaults,
administrator checks, and the opt-in gate around command/PHP execution
services. Use concise Conventional Commits such as
`fix: reject credential-bearing URLs`. Pull requests should explain behavior
and risk, link relevant issues, list validation run, and include screenshots
for visible UI changes. Update `CHANGELOG.md` for user-facing changes. Release
tags must use `vX.Y.Z` and match the version in `manifest.json`.
