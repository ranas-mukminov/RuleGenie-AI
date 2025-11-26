from fastapi import APIRouter, Depends
from sqlmodel import Session

from ...db import get_session
from ...domain.ai_client import DummyRuleLLMClient, RuleGenParams
from ...schemas import AIDryRunRequest, GenericRuleResponse

router = APIRouter()


@router.post("/dry-run-description", response_model=GenericRuleResponse)
async def dry_run_description(payload: AIDryRunRequest, session: Session = Depends(get_session)) -> GenericRuleResponse:
    llm_client = DummyRuleLLMClient()
    params = RuleGenParams(target_type=payload.target_type)
    generic_rule = await llm_client.generate_rule_from_description(payload.description, payload.logsource, params)
    return GenericRuleResponse(generic_rule=generic_rule)
