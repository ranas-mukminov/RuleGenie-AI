from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import Column, JSON, Text
from sqlmodel import Field, SQLModel


class Workspace(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class LogSourceProfile(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id")
    name: str
    description: Optional[str] = None
    platform: Optional[str] = None
    product: Optional[str] = None
    log_format: Optional[str] = Field(default="json", description="json/kv/raw")
    field_mappings: Dict[str, str] = Field(default_factory=dict, sa_column=Column(JSON))
    sample_schema: Optional[Dict] = Field(default=None, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class DetectionRule(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id")
    name: str
    description: Optional[str] = None
    status: str = Field(default="draft")
    severity: Optional[str] = None
    category: Optional[str] = None
    mitre_techniques: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    tags: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    primary_logsource_id: Optional[int] = Field(default=None, foreign_key="logsourceprofile.id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class RuleVersion(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    rule_id: int = Field(foreign_key="detectionrule.id")
    version_number: int
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = Field(default="system")
    source_type: str = Field(default="ai_draft")
    target_type: str = Field(default="generic")
    content: str = Field(sa_column=Column(Text))
    metadata: Dict = Field(default_factory=dict, sa_column=Column(JSON))
    changelog: Optional[str] = None
    is_active: bool = Field(default=True)


class RuleGenerationRequest(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id")
    rule_id: Optional[int] = Field(default=None, foreign_key="detectionrule.id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    input_type: str
    raw_prompt: str
    parameters: Dict = Field(default_factory=dict, sa_column=Column(JSON))
    status: str = Field(default="completed")
    output_rule_version_id: Optional[int] = Field(default=None, foreign_key="ruleversion.id")


class LogSampleSet(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    workspace_id: int = Field(foreign_key="workspace.id")
    name: str
    description: Optional[str] = None
    logsource_id: Optional[int] = Field(default=None, foreign_key="logsourceprofile.id")
    format: str = Field(default="json")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class LogSample(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    sample_set_id: int = Field(foreign_key="logsampleset.id")
    raw_log: str
    is_malicious: bool = Field(default=False)
    label_metadata: Dict = Field(default_factory=dict, sa_column=Column(JSON))
    parsed_event: Optional[Dict] = Field(default=None, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=datetime.utcnow)


class RuleEvaluationRun(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    rule_version_id: int = Field(foreign_key="ruleversion.id")
    sample_set_id: int = Field(foreign_key="logsampleset.id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    status: str = Field(default="completed")
    metrics: Dict = Field(default_factory=dict, sa_column=Column(JSON))
    details: Optional[Dict] = Field(default=None, sa_column=Column(JSON))


class RuleTemplate(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    description: Optional[str] = None
    template_body: Dict = Field(default_factory=dict, sa_column=Column(JSON))
    parameters_schema: Optional[Dict] = Field(default=None, sa_column=Column(JSON))
