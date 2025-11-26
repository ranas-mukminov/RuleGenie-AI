from typing import List

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlmodel import Session, select

from ...db import get_session
from ...domain.ai_client import DummyRuleLLMClient, RuleGenParams
from ...domain.dsl import LogSource
from ...domain.rules import (
    create_rule_version,
    generate_rule_from_description,
    generate_rule_from_samples,
    get_active_generic_rule,
    serialize_generic_rule,
)
from ...domain.sigma_export import generic_rule_to_sigma
from ...models import (
    DetectionRule,
    LogSample,
    LogSampleSet,
    LogSourceProfile,
    RuleEvaluationRun,
    RuleGenerationRequest,
    RuleVersion,
)
from ...schemas import (
    DetectionRuleCreate,
    DetectionRuleRead,
    GenericRuleResponse,
    RuleGenFromDescriptionRequest,
    RuleGenFromSamplesRequest,
    RuleGenerationRequestRead,
    RuleVersionRead,
)

router = APIRouter()


def _logsource_from_profile(profile: LogSourceProfile | None) -> LogSource | None:
    if not profile:
        return None
    return LogSource(
        platform=profile.platform,
        product=profile.product,
        service=profile.description,
        category=profile.log_format,
    )


@router.post("/workspaces/{workspace_id}/rules", response_model=DetectionRuleRead)
def create_rule(workspace_id: int, payload: DetectionRuleCreate, session: Session = Depends(get_session)) -> DetectionRule:
    rule = DetectionRule(
        workspace_id=workspace_id,
        name=payload.name,
        description=payload.description,
        status=payload.status,
        severity=payload.severity,
        category=payload.category,
        mitre_techniques=payload.mitre_techniques,
        tags=payload.tags,
        primary_logsource_id=payload.primary_logsource_id,
    )
    session.add(rule)
    session.commit()
    session.refresh(rule)
    return rule


@router.get("/workspaces/{workspace_id}/rules", response_model=List[DetectionRuleRead])
def list_rules(workspace_id: int, session: Session = Depends(get_session)) -> List[DetectionRule]:
    statement = select(DetectionRule).where(DetectionRule.workspace_id == workspace_id)
    return session.exec(statement).all()


@router.get("/rules/{rule_id}", response_model=DetectionRuleRead)
def get_rule(rule_id: int, session: Session = Depends(get_session)) -> DetectionRule:
    rule = session.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.post("/rules/{rule_id}/versions/ai-from-description", response_model=RuleVersionRead)
async def generate_version_from_description(
    rule_id: int, payload: RuleGenFromDescriptionRequest, session: Session = Depends(get_session)
) -> RuleVersion:
    rule = session.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    profile = session.get(LogSourceProfile, payload.logsource_id) if payload.logsource_id else None
    llm_client = DummyRuleLLMClient()
    params = RuleGenParams(target_type=payload.target_type)
    generic_rule = await generate_rule_from_description(llm_client, payload.description, _logsource_from_profile(profile), params)
    version = create_rule_version(
        session=session,
        rule=rule,
        generic_rule=generic_rule,
        target_type=payload.target_type,
        created_by="ai",
        source_type="ai_draft",
        changelog=payload.changelog or "Generated from description",
    )
    gen_req = RuleGenerationRequest(
        workspace_id=rule.workspace_id,
        rule_id=rule.id,
        input_type="threat_description",
        raw_prompt=payload.description,
        parameters=payload.model_dump(),
        status="completed",
        output_rule_version_id=version.id,
    )
    session.add(gen_req)
    session.commit()
    return version


@router.post("/rules/{rule_id}/versions/ai-from-samples", response_model=RuleVersionRead)
async def generate_version_from_samples(
    rule_id: int, payload: RuleGenFromSamplesRequest, session: Session = Depends(get_session)
) -> RuleVersion:
    rule = session.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    sample_set = session.get(LogSampleSet, payload.sample_set_id)
    if not sample_set:
        raise HTTPException(status_code=404, detail="Sample set not found")
    samples = session.exec(select(LogSample).where(LogSample.sample_set_id == sample_set.id)).all()
    llm_client = DummyRuleLLMClient()
    params = RuleGenParams(target_type=payload.target_type)
    generic_rule = await generate_rule_from_samples(llm_client, samples, payload.description, params)
    version = create_rule_version(
        session=session,
        rule=rule,
        generic_rule=generic_rule,
        target_type=payload.target_type,
        created_by="ai",
        source_type="ai_draft",
        changelog=payload.changelog or "Generated from samples",
    )
    gen_req = RuleGenerationRequest(
        workspace_id=rule.workspace_id,
        rule_id=rule.id,
        input_type="log_samples",
        raw_prompt=payload.description or "",
        parameters=payload.model_dump(),
        status="completed",
        output_rule_version_id=version.id,
    )
    session.add(gen_req)
    session.commit()
    return version


@router.get("/rules/{rule_id}/versions", response_model=List[RuleVersionRead])
def list_rule_versions(rule_id: int, session: Session = Depends(get_session)) -> List[RuleVersion]:
    return session.exec(select(RuleVersion).where(RuleVersion.rule_id == rule_id)).all()


@router.get("/rule-versions/{version_id}", response_model=RuleVersionRead)
def get_rule_version(version_id: int, session: Session = Depends(get_session)) -> RuleVersion:
    version = session.get(RuleVersion, version_id)
    if not version:
        raise HTTPException(status_code=404, detail="Rule version not found")
    return version


@router.get("/rule-versions/{version_id}/export/sigma")
def export_sigma(version_id: int, session: Session = Depends(get_session)) -> Response:
    version = session.get(RuleVersion, version_id)
    if not version:
        raise HTTPException(status_code=404, detail="Rule version not found")
    generic_rule = get_active_generic_rule(version)
    sigma_content = generic_rule_to_sigma(generic_rule)
    return Response(content=sigma_content, media_type="text/yaml")


@router.get("/rule-versions/{version_id}/export/generic", response_model=GenericRuleResponse)
def export_generic(version_id: int, session: Session = Depends(get_session)) -> GenericRuleResponse:
    version = session.get(RuleVersion, version_id)
    if not version:
        raise HTTPException(status_code=404, detail="Rule version not found")
    generic_rule = get_active_generic_rule(version)
    return GenericRuleResponse(generic_rule=generic_rule)
