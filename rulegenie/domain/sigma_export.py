from __future__ import annotations

import re
from typing import Dict

import yaml

from .dsl import GenericRule, split_field_operator


def _selection_to_sigma(selection: Dict[str, object]) -> Dict[str, object]:
    rendered: Dict[str, object] = {}
    for key, value in selection.items():
        field, op = split_field_operator(key)
        if op == "equals":
            rendered[field] = value
        else:
            rendered[f"{field}|{op}"] = value
    return rendered


def generic_rule_to_sigma(rule: GenericRule) -> str:
    """Render a subset of Sigma YAML for the given generic rule."""
    detection: Dict[str, object] = {}
    for name, selection in rule.detection.selections.items():
        detection[name] = _selection_to_sigma(selection)
    detection["condition"] = rule.detection.condition

    sigma_dict: Dict[str, object] = {
        "title": rule.title,
        "description": rule.description or "",
        "logsource": rule.logsource.model_dump(exclude_none=True) if rule.logsource else {},
        "detection": detection,
        "fields": rule.fields or [],
        "tags": rule.tags or [],
    }
    if rule.severity:
        sigma_dict["level"] = rule.severity
    if rule.mitre:
        sigma_dict["references"] = rule.mitre

    return yaml.safe_dump(sigma_dict, sort_keys=False, allow_unicode=False)


def _selection_to_query(selection: Dict[str, object]) -> str:
    parts = []
    for key, value in selection.items():
        field, op = split_field_operator(key)
        if op == "equals":
            parts.append(f"{field} == {value!r}")
        elif op == "contains":
            parts.append(f"contains({field}, {value!r})")
        elif op == "startswith":
            parts.append(f"startswith({field}, {value!r})")
        elif op == "endswith":
            parts.append(f"endswith({field}, {value!r})")
        elif op == "in":
            parts.append(f"{field} IN {value!r}")
        elif op == "not_in":
            parts.append(f"{field} NOT IN {value!r}")
        elif op == "gt":
            parts.append(f"{field} > {value!r}")
        elif op == "gte":
            parts.append(f"{field} >= {value!r}")
        elif op == "lt":
            parts.append(f"{field} < {value!r}")
        elif op == "lte":
            parts.append(f"{field} <= {value!r}")
    return " AND ".join(parts)


def generic_rule_to_pseudo_query(rule: GenericRule) -> str:
    selection_queries = {name: f"({ _selection_to_query(sel) })" for name, sel in rule.detection.selections.items()}
    condition = rule.detection.condition
    for name, clause in selection_queries.items():
        condition = re.sub(rf"\b{name}\b", lambda _: clause, condition)
    condition = condition.replace("and", "AND").replace("or", "OR").replace("not", "NOT")
    if rule.detection.aggregation:
        agg = rule.detection.aggregation
        condition = f"{condition} | AGG {agg.op}({agg.field or '*'}) > {agg.threshold} WITHIN {agg.window}"
    return condition
