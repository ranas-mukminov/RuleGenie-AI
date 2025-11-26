# RuleGenie AI

AI-assisted detection rule generator and evaluator for SOC teams. Converts threat descriptions and sample logs into draft detection content (generic DSL, Sigma/pseudo queries), evaluates against labeled logs, and keeps rule versions accessible via API and CLI.

## Features
- Generic detection DSL with Sigma export.
- AI-assisted draft generation (offline dummy LLM, pluggable real provider stub).
- Rule versioning and metadata.
- Evaluation engine with precision/recall metrics on labeled logs.
- FastAPI backend + Typer CLI for local workflows.
- SQLite by default; ready for PostgreSQL via `RULEGENIE_DATABASE_URL`.

## Quickstart
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run API
uvicorn rulegenie.api.main:app --reload

# Create a workspace via CLI
rulegenie init-workspace --name "My SOC"

# Import logs (JSONL)
rulegenie import-logs --workspace-id 1 --file examples/logs/windows_powershell.jsonl --name "ps-logs"

# Generate a rule from description
rulegenie generate-from-description --workspace-id 1 --name "Encoded PS" --description "Detect PowerShell encoded command" --target sigma --output generated_rule.yaml

# Evaluate a generic rule file against logs
rulegenie evaluate --rule-file examples/rules/powershell_encoded_command_generic.yaml --logs examples/logs/windows_powershell.jsonl
```

## API Overview
- `POST /workspaces` create workspace; `GET /workspaces` list.
- `POST /workspaces/{id}/sample-sets` create log sample set (with samples).
- `POST /workspaces/{id}/rules` create rule metadata; `GET /workspaces/{id}/rules` list.
- `POST /rules/{id}/versions/ai-from-description` generate rule version via dummy AI.
- `POST /rules/{id}/versions/ai-from-samples` generate from log samples.
- `POST /rule-versions/{id}/evaluate` run evaluation on a sample set.
- `GET /rule-versions/{id}/export/sigma` export as Sigma YAML.
- `POST /ai/dry-run-description` simulate AI output without persisting.

Launch docs with the interactive Swagger UI at `/docs`.

## Configuration
Environment variables (prefix `RULEGENIE_`):
- `DATABASE_URL` (default `sqlite:///./rulegenie.db`)
- `API_KEY` (optional, enforces `X-API-Key` header)
- `LLM_PROVIDER`, `LLM_API_KEY` (placeholders for future real provider)

## Project Layout
- `rulegenie/domain`: DSL, Sigma export, AI abstraction, evaluation engine.
- `rulegenie/api`: FastAPI app and routers.
- `rulegenie/cli`: Typer CLI entrypoint.
- `tests`: pytest suites for DSL, sigma export, evaluation, dummy AI.
- `examples`: sample logs and rules.
- `docs`: architecture and DSL details.

## Testing
```bash
pytest
```

## Security & Privacy
- No secrets in code; all credentials via environment.
- Offline dummy AI avoids sending logs externally.
- Designed for defensive detection engineering use only.
