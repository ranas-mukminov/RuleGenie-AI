from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from ...db import get_session
from ...domain.evaluation import run_evaluation
from ...domain.rules import get_active_generic_rule
from ...models import LogSample, LogSampleSet, RuleEvaluationRun, RuleVersion
from ...schemas import EvaluationRequest, EvaluationResult

router = APIRouter()


@router.post("/rule-versions/{version_id}/evaluate", response_model=EvaluationResult)
def evaluate_rule_version(
    version_id: int, payload: EvaluationRequest, session: Session = Depends(get_session)
) -> EvaluationResult:
    rule_version = session.get(RuleVersion, version_id)
    if not rule_version:
        raise HTTPException(status_code=404, detail="Rule version not found")
    sample_set = session.get(LogSampleSet, payload.sample_set_id)
    if not sample_set:
        raise HTTPException(status_code=404, detail="Sample set not found")

    samples: List[LogSample] = session.exec(select(LogSample).where(LogSample.sample_set_id == sample_set.id)).all()
    generic_rule = get_active_generic_rule(rule_version)
    metrics, details = run_evaluation(generic_rule, samples)

    run = RuleEvaluationRun(
        rule_version_id=version_id,
        sample_set_id=sample_set.id,
        status="completed",
        metrics=metrics,
        details=[detail.__dict__ for detail in details],
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    return EvaluationResult(run_id=run.id, status=run.status, metrics=metrics, details=run.details)


@router.get("/evals/{run_id}", response_model=EvaluationResult)
def get_evaluation(run_id: int, session: Session = Depends(get_session)) -> EvaluationResult:
    run = session.get(RuleEvaluationRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Evaluation run not found")
    return EvaluationResult(run_id=run.id, status=run.status, metrics=run.metrics, details=run.details)
