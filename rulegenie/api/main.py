from fastapi import Depends, FastAPI, HTTPException, Request, status

from ..config import get_settings
from ..db import init_db
from .routers import ai, evaluations, logs, rules, workspaces

settings = get_settings()


async def require_api_key(request: Request) -> None:
    if not settings.api_key:
        return
    api_key = request.headers.get("x-api-key")
    if api_key != settings.api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


dependencies = [Depends(require_api_key)] if settings.api_key else []
app = FastAPI(
    title="RuleGenie AI",
    version="0.1.0",
    description="AI-assisted detection rule generator and evaluator.",
    dependencies=dependencies,
)


@app.on_event("startup")
def startup_event() -> None:
    init_db()


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


app.include_router(workspaces.router, prefix="/workspaces", tags=["workspaces"])
app.include_router(logs.router, tags=["logs"])
app.include_router(rules.router, tags=["rules"])
app.include_router(evaluations.router, tags=["evaluations"])
app.include_router(ai.router, prefix="/ai", tags=["ai"])
