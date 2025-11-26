from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .domain.dsl import GenericRule, LogSource


class WorkspaceCreate(BaseModel):
    name: str
    description: Optional[str] = None


class WorkspaceRead(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LogSourceProfileCreate(BaseModel):
    name: str
    description: Optional[str] = None
    platform: Optional[str] = None
    product: Optional[str] = None
    log_format: Optional[str] = "json"
    field_mappings: Dict[str, str] = Field(default_factory=dict)
    sample_schema: Optional[Dict[str, Any]] = None


class LogSourceProfileRead(LogSourceProfileCreate):
    id: int
    workspace_id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LogSampleIn(BaseModel):
    raw_log: str
    is_malicious: bool = False
    label_metadata: Dict[str, Any] = Field(default_factory=dict)


class LogSampleRead(LogSampleIn):
    id: int
    sample_set_id: int
    parsed_event: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LogSampleSetCreate(BaseModel):
    name: str
    description: Optional[str] = None
    logsource_id: Optional[int] = None
    format: str = "json"
    samples: List[LogSampleIn] = Field(default_factory=list)


class LogSampleSetRead(LogSampleSetCreate):
    id: int
    workspace_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DetectionRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    status: str = "draft"
    severity: Optional[str] = None
    category: Optional[str] = None
    mitre_techniques: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    primary_logsource_id: Optional[int] = None


class DetectionRuleRead(DetectionRuleCreate):
    id: int
    workspace_id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RuleVersionRead(BaseModel):
    id: int
    rule_id: int
    version_number: int
    created_at: datetime
    created_by: str
    source_type: str
    target_type: str
    content: str
    metadata: Dict[str, Any]
    changelog: Optional[str] = None
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class RuleGenerationRequestRead(BaseModel):
    id: int
    workspace_id: int
    rule_id: Optional[int]
    created_at: datetime
    input_type: str
    raw_prompt: str
    parameters: Dict[str, Any]
    status: str
    output_rule_version_id: Optional[int]

    model_config = ConfigDict(from_attributes=True)


class RuleGenFromDescriptionRequest(BaseModel):
    description: str
    target_type: str = "generic"
    logsource_id: Optional[int] = None
    severity: Optional[str] = None
    mitre_techniques: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    changelog: Optional[str] = None


class RuleGenFromSamplesRequest(BaseModel):
    sample_set_id: int
    description: Optional[str] = None
    target_type: str = "generic"
    changelog: Optional[str] = None


class EvaluationRequest(BaseModel):
    sample_set_id: int


class EvaluationResult(BaseModel):
    run_id: int
    status: str
    metrics: Dict[str, Any]
    details: Optional[Dict[str, Any]] = None


class AIDryRunRequest(BaseModel):
    description: str
    logsource: Optional[LogSource] = None
    target_type: str = "generic"


class GenericRuleResponse(BaseModel):
    generic_rule: GenericRule
