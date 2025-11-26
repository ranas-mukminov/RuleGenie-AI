# RuleGenie AI Architecture

## Domain model
- **Workspace** – scope for a team/project.
- **LogSourceProfile** – describes platform/product/format and field mappings.
- **DetectionRule** – logical rule metadata.
- **RuleVersion** – versioned content body, target type (generic/sigma/pseudo).
- **RuleGenerationRequest** – records AI generation attempts.
- **LogSampleSet / LogSample** – labeled logs for training/evaluation.
- **RuleEvaluationRun** – stores evaluation metrics and details.
- **RuleTemplate** – optional reusable patterns.

### ASCII ERD
```
Workspace 1---* LogSourceProfile
Workspace 1---* DetectionRule
Workspace 1---* LogSampleSet
LogSampleSet 1---* LogSample
DetectionRule 1---* RuleVersion
RuleVersion 1---* RuleEvaluationRun
RuleGenerationRequest *---1 Workspace
RuleGenerationRequest *---1 DetectionRule (optional)
RuleGenerationRequest 1---1 RuleVersion (optional output)
LogSourceProfile 1---* DetectionRule (primary_logsource)
```

## Components
- **DSL (`rulegenie/domain/dsl.py`)**: GenericRule model, validation, operators.
- **Sigma export (`domain/sigma_export.py`)**: generic → Sigma YAML or pseudo query.
- **AI abstraction (`domain/ai_client.py`)**: protocol, dummy offline generator, stub for real provider.
- **Rule engine (`domain/evaluation.py`)**: selection evaluation, safe condition parsing, metrics.
- **Log ingest (`domain/log_ingest.py`)**: JSON/kv parsing helpers.
- **API (`rulegenie/api`)**: FastAPI app with routers for workspaces, logs, rules/versions, evaluations, AI dry-run.
- **CLI (`rulegenie/cli`)**: Typer commands reusing domain logic.

## Core flows
### A) Generate from description
1. API/CLI receives description + params.
2. Build RuleGenerationRequest entry.
3. Dummy LLM → `GenericRule`.
4. Convert to target (Sigma/pseudo/generic) and create `RuleVersion`.
5. RuleVersion stored, linked to request; optional evaluation.

### B) Generate from log samples
1. Ingest logs into `LogSampleSet`.
2. Dummy LLM inspects samples → candidate `GenericRule`.
3. Store as `RuleVersion`.
4. Evaluate on provided sample set; store metrics in `RuleEvaluationRun`.

### C) Iterative refinement
1. User edits/feedback → new `RuleVersion` (source_type manual/ai_draft).
2. Optional AI refine.
3. Re-evaluate and compare metrics.

### D) Evaluation flow
1. Fetch `RuleVersion` + `LogSampleSet`.
2. Convert to `GenericRule`.
3. Evaluate selections + condition against each event.
4. Compute TP/FP/FN/TN, precision/recall/F1.
5. Persist `RuleEvaluationRun.metrics` and details.

## Notes for future hardening
- Swap SQLite for PostgreSQL by changing `RULEGENIE_DATABASE_URL`.
- Add auth/multi-tenant layers and RBAC.
- Replace dummy AI with real provider via `RuleLLMClient` implementation.
- Offload evaluations to background workers/queue for large log sets.
