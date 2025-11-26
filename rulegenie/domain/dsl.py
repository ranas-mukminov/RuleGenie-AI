from __future__ import annotations

import re
from typing import Any, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, Field, field_validator, model_validator

ALLOWED_OPERATORS = {
    "equals",
    "contains",
    "startswith",
    "endswith",
    "in",
    "not_in",
    "gt",
    "gte",
    "lt",
    "lte",
}


def split_field_operator(key: str) -> Tuple[str, str]:
    """Split field|operator into components; default operator is equals."""
    if "|" in key:
        field, op = key.split("|", 1)
    else:
        field, op = key, "equals"
    return field, op


class LogSource(BaseModel):
    platform: Optional[str] = None
    product: Optional[str] = None
    service: Optional[str] = None
    category: Optional[str] = None


class Aggregation(BaseModel):
    op: Literal["count", "distinct_count"]
    field: Optional[str] = None
    threshold: int
    window: str  # e.g., "5m", "1h"


class DetectionBlock(BaseModel):
    selections: Dict[str, Dict[str, Any]]
    condition: str
    timeframe: Optional[str] = None
    aggregation: Optional[Aggregation] = None

    @field_validator("selections")
    @classmethod
    def validate_selection_ops(cls, v: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        for selection_name, body in v.items():
            if not body:
                raise ValueError(f"Selection {selection_name} is empty")
            for key in body.keys():
                _, op = split_field_operator(key)
                if op not in ALLOWED_OPERATORS:
                    raise ValueError(f"Unsupported operator '{op}' in selection '{selection_name}'")
        return v


class GenericRule(BaseModel):
    title: str
    description: Optional[str] = None
    logsource: Optional[LogSource] = None
    detection: DetectionBlock
    fields: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    severity: Optional[str] = None
    mitre: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_condition(self) -> "GenericRule":
        names = set(self.detection.selections.keys())
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", self.detection.condition)
        missing = [t for t in tokens if t not in names and t not in {"and", "or", "not"}]
        if missing:
            raise ValueError(f"Condition references undefined selections: {missing}")
        return self

    def referenced_selections(self) -> List[str]:
        return list(self.detection.selections.keys())

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
