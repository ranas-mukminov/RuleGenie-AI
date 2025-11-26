import json
from typing import Optional

import yaml
from sqlmodel import Session, select

from .ai_client import RuleGenParams, RuleLLMClient
from .dsl import GenericRule
from .sigma_export import generic_rule_to_pseudo_query, generic_rule_to_sigma
from ..models import DetectionRule, RuleGenerationRequest, RuleVersion


def serialize_generic_rule(rule: GenericRule) -> str:
    return json.dumps(rule.model_dump())


def deserialize_generic_rule(content: str) -> GenericRule:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        data = yaml.safe_load(content)
    return GenericRule.model_validate(data)


def next_version_number(session: Session, rule_id: int) -> int:
    result = session.exec(select(RuleVersion).where(RuleVersion.rule_id == rule_id)).all()
    if not result:
        return 1
    return max(rv.version_number for rv in result) + 1


def create_rule_version(
    session: Session,
    rule: DetectionRule,
    generic_rule: GenericRule,
    target_type: str,
    created_by: str = "system",
    source_type: str = "ai_draft",
    changelog: Optional[str] = None,
) -> RuleVersion:
    if target_type == "sigma":
        content = generic_rule_to_sigma(generic_rule)
    elif target_type in {"spl", "kql", "pseudo"}:
        content = generic_rule_to_pseudo_query(generic_rule)
    else:
        target_type = "generic"
        content = serialize_generic_rule(generic_rule)

    version = RuleVersion(
        rule_id=rule.id,
        version_number=next_version_number(session, rule.id),
        created_by=created_by,
        source_type=source_type,
        target_type=target_type,
        content=content,
        metadata={"generic_rule": generic_rule.model_dump()},
        changelog=changelog,
        is_active=True,
    )
    session.add(version)
    session.commit()
    session.refresh(version)
    return version


async def generate_rule_from_description(
    llm_client: RuleLLMClient,
    description: str,
    logsource,
    params: RuleGenParams,
) -> GenericRule:
    return await llm_client.generate_rule_from_description(description, logsource, params)


async def generate_rule_from_samples(
    llm_client: RuleLLMClient,
    samples,
    description: Optional[str],
    params: RuleGenParams,
) -> GenericRule:
    return await llm_client.generate_rule_from_samples(samples, description, params)


def get_active_generic_rule(rule_version: RuleVersion) -> GenericRule:
    if rule_version.metadata and "generic_rule" in rule_version.metadata:
        return GenericRule.model_validate(rule_version.metadata["generic_rule"])
    return deserialize_generic_rule(rule_version.content)
