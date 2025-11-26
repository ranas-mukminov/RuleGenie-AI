from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import typer
import yaml
from sqlmodel import Session

from ..db import engine, init_db
from ..domain.ai_client import DummyRuleLLMClient, RuleGenParams
from ..domain.dsl import GenericRule
from ..domain.evaluation import run_evaluation
from ..domain.log_ingest import load_events_from_jsonl
from ..domain.rules import create_rule_version
from ..models import DetectionRule, LogSample, Workspace

app = typer.Typer(help="RuleGenie AI CLI")


def _load_generic_rule_from_file(path: Path) -> GenericRule:
    content = path.read_text()
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        data = json.loads(content)
    return GenericRule.model_validate(data)


@app.command("init-workspace")
def init_workspace(name: str = typer.Option(..., help="Workspace name"), description: str = "") -> None:
    init_db()
    with Session(engine) as session:
        ws = Workspace(name=name, description=description)
        session.add(ws)
        session.commit()
        typer.echo(f"Created workspace id={ws.id} name={ws.name}")


@app.command("import-logs")
def import_logs(
    workspace_id: int = typer.Option(..., help="Workspace id"),
    file: Path = typer.Option(..., help="Path to JSONL logs"),
    name: str = typer.Option("imported logs", help="Sample set name"),
    malicious: bool = typer.Option(False, help="Mark imported logs as malicious"),
    logsource_id: Optional[int] = typer.Option(None, help="Optional logsource id"),
) -> None:
    init_db()
    events = load_events_from_jsonl(file)
    with Session(engine) as session:
        sample_set = LogSampleSet(
            workspace_id=workspace_id,
            name=name,
            description=f"Imported from {file}",
            logsource_id=logsource_id,
        )
        session.add(sample_set)
        session.commit()
        session.refresh(sample_set)
        for event in events:
            session.add(
                LogSample(
                    sample_set_id=sample_set.id,
                    raw_log=json.dumps(event),
                    parsed_event=event,
                    is_malicious=malicious,
                )
            )
        session.commit()
        typer.echo(f"Imported {len(events)} logs into sample set {sample_set.id}")


@app.command("generate-from-description")
def generate_from_description(
    workspace_id: int = typer.Option(..., help="Workspace id"),
    name: str = typer.Option(..., help="Rule name"),
    description: str = typer.Option(..., help="Threat description"),
    target: str = typer.Option("generic", help="Target type: generic|sigma|pseudo"),
    output: Optional[Path] = typer.Option(None, help="Optional path to write the generated rule content"),
) -> None:
    init_db()
    with Session(engine) as session:
        detection_rule = DetectionRule(workspace_id=workspace_id, name=name, description=description, status="draft")
        session.add(detection_rule)
        session.commit()
        session.refresh(detection_rule)

        llm_client = DummyRuleLLMClient()
        params = RuleGenParams(target_type=target)
        generic_rule = asyncio.run(llm_client.generate_rule_from_description(description, None, params))
        version = create_rule_version(
            session=session,
            rule=detection_rule,
            generic_rule=generic_rule,
            target_type=target,
            created_by="cli",
            source_type="ai_draft",
            changelog="CLI generation",
        )
        typer.echo(f"Created rule version {version.id} with target_type={version.target_type}")
        if output:
            output.write_text(version.content)
            typer.echo(f"Wrote rule content to {output}")


@app.command("evaluate")
def evaluate(
    rule_file: Path = typer.Option(..., help="Generic rule file (YAML/JSON)"),
    logs: Path = typer.Option(..., help="Logs in JSONL"),
) -> None:
    rule = _load_generic_rule_from_file(rule_file)
    events = load_events_from_jsonl(logs)
    labels = [bool(event.get("is_malicious", False)) for event in events]
    samples = [
        SimpleNamespace(is_malicious=label, parsed_event=event, raw_log=json.dumps(event))
        for event, label in zip(events, labels)
    ]
    metrics, _ = run_evaluation(rule, samples)
    typer.echo(f"Evaluated {len(events)} events. Metrics: {metrics}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
