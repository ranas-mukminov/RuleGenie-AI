from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from ...db import get_session
from ...models import Workspace
from ...schemas import WorkspaceCreate, WorkspaceRead

router = APIRouter()


@router.post("", response_model=WorkspaceRead)
def create_workspace(payload: WorkspaceCreate, session: Session = Depends(get_session)) -> Workspace:
    existing = session.exec(select(Workspace).where(Workspace.name == payload.name)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Workspace with this name already exists")
    workspace = Workspace(name=payload.name, description=payload.description)
    session.add(workspace)
    session.commit()
    session.refresh(workspace)
    return workspace


@router.get("", response_model=List[WorkspaceRead])
def list_workspaces(session: Session = Depends(get_session)) -> List[Workspace]:
    return session.exec(select(Workspace)).all()
