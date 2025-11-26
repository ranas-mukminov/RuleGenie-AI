from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from ...db import get_session
from ...domain.log_ingest import parse_event
from ...models import LogSample, LogSampleSet, Workspace
from ...schemas import LogSampleRead, LogSampleSetCreate, LogSampleSetRead

router = APIRouter()


@router.post("/workspaces/{workspace_id}/sample-sets", response_model=LogSampleSetRead)
def create_sample_set(
    workspace_id: int, payload: LogSampleSetCreate, session: Session = Depends(get_session)
) -> LogSampleSet:
    workspace = session.get(Workspace, workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")
    sample_set = LogSampleSet(
        workspace_id=workspace_id,
        name=payload.name,
        description=payload.description,
        logsource_id=payload.logsource_id,
        format=payload.format,
    )
    session.add(sample_set)
    session.commit()
    session.refresh(sample_set)

    for sample in payload.samples:
        parsed = parse_event(sample.raw_log)
        sample_row = LogSample(
            sample_set_id=sample_set.id,
            raw_log=sample.raw_log,
            is_malicious=sample.is_malicious,
            label_metadata=sample.label_metadata,
            parsed_event=parsed,
        )
        session.add(sample_row)
    session.commit()
    return sample_set


@router.get("/sample-sets/{sample_set_id}", response_model=LogSampleSetRead)
def get_sample_set(sample_set_id: int, session: Session = Depends(get_session)) -> LogSampleSet:
    sample_set = session.get(LogSampleSet, sample_set_id)
    if not sample_set:
        raise HTTPException(status_code=404, detail="Sample set not found")
    return sample_set


@router.get("/sample-sets/{sample_set_id}/samples", response_model=List[LogSampleRead])
def list_samples(
    sample_set_id: int,
    limit: int = Query(100, le=500),
    offset: int = 0,
    session: Session = Depends(get_session),
) -> List[LogSample]:
    sample_set = session.get(LogSampleSet, sample_set_id)
    if not sample_set:
        raise HTTPException(status_code=404, detail="Sample set not found")
    statement = (
        select(LogSample).where(LogSample.sample_set_id == sample_set_id).offset(offset).limit(limit)
    )
    return session.exec(statement).all()
