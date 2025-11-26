from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .dsl import GenericRule, split_field_operator
from .log_ingest import parse_event


def _apply_operator(event_value: Any, operator: str, target: Any) -> bool:
    if operator == "equals":
        return event_value == target
    if operator == "contains":
        return str(target).lower() in str(event_value).lower()
    if operator == "startswith":
        return str(event_value).startswith(str(target))
    if operator == "endswith":
        return str(event_value).endswith(str(target))
    if operator == "in":
        return event_value in target if isinstance(target, (list, tuple, set)) else False
    if operator == "not_in":
        return event_value not in target if isinstance(target, (list, tuple, set)) else False
    if operator == "gt":
        try:
            return float(event_value) > float(target)
        except (TypeError, ValueError):
            return False
    if operator == "gte":
        try:
            return float(event_value) >= float(target)
        except (TypeError, ValueError):
            return False
    if operator == "lt":
        try:
            return float(event_value) < float(target)
        except (TypeError, ValueError):
            return False
    if operator == "lte":
        try:
            return float(event_value) <= float(target)
        except (TypeError, ValueError):
            return False
    return False


def evaluate_selection(selection: Dict[str, Any], event: Dict[str, Any]) -> bool:
    for key, target in selection.items():
        field, operator = split_field_operator(key)
        if field not in event:
            return False
        value = event.get(field)
        if not _apply_operator(value, operator, target):
            return False
    return True


def _safe_eval_condition(condition: str, context: Dict[str, bool]) -> bool:
    tree = ast.parse(condition, mode="eval")
    allowed_nodes = (
        ast.Expression,
        ast.BoolOp,
        ast.UnaryOp,
        ast.Name,
        ast.Load,
        ast.And,
        ast.Or,
        ast.Not,
        ast.Constant,
        ast.Expr,
    )

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id not in context:
            raise ValueError(f"Unknown selection '{node.id}' in condition")
        if not isinstance(node, allowed_nodes):
            raise ValueError("Unsupported expression in condition")
    return bool(eval(compile(tree, filename="<condition>", mode="eval"), {}, context))


def evaluate_rule_on_event(rule: GenericRule, event: Dict[str, Any]) -> Tuple[bool, Dict[str, bool]]:
    selection_results: Dict[str, bool] = {}
    for name, selection in rule.detection.selections.items():
        selection_results[name] = evaluate_selection(selection, event)
    match = _safe_eval_condition(rule.detection.condition, selection_results)
    return match, selection_results


def evaluate_rule_on_events(rule: GenericRule, events: Iterable[Dict[str, Any]]) -> List[bool]:
    results: List[bool] = []
    for event in events:
        match, _ = evaluate_rule_on_event(rule, event)
        results.append(match)
    return results


@dataclass
class EvaluationDetail:
    matched: bool
    label: bool
    sample_id: Optional[int]
    selection_results: Dict[str, bool]


def compute_metrics(labels: List[bool], matches: List[bool]) -> Dict[str, Any]:
    assert len(labels) == len(matches)
    tp = sum(1 for l, m in zip(labels, matches) if l and m)
    fp = sum(1 for l, m in zip(labels, matches) if not l and m)
    fn = sum(1 for l, m in zip(labels, matches) if l and not m)
    tn = sum(1 for l, m in zip(labels, matches) if not l and not m)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def run_evaluation(rule: GenericRule, samples: Iterable[Any]) -> Tuple[Dict[str, Any], List[EvaluationDetail]]:
    labels: List[bool] = []
    matches: List[bool] = []
    details: List[EvaluationDetail] = []
    for sample in samples:
        label = bool(getattr(sample, "is_malicious", False))
        event = getattr(sample, "parsed_event", None) or parse_event(getattr(sample, "raw_log", ""))
        matched, selection_results = evaluate_rule_on_event(rule, event)
        labels.append(label)
        matches.append(matched)
        details.append(
            EvaluationDetail(
                matched=matched,
                label=label,
                sample_id=getattr(sample, "id", None),
                selection_results=selection_results,
            )
        )

    metrics = compute_metrics(labels, matches)
    return metrics, details
