from __future__ import annotations

import os
from typing import Iterable, Optional, Protocol

from pydantic import BaseModel

from .dsl import DetectionBlock, GenericRule, LogSource
from .log_ingest import parse_event


class RuleGenParams(BaseModel):
    target_type: str = "generic"
    sensitivity: str = "normal"
    language: str = "en"


class RuleLLMClient(Protocol):
    async def generate_rule_from_description(
        self, description: str, logsource: Optional[LogSource], params: RuleGenParams
    ) -> GenericRule:
        ...

    async def generate_rule_from_samples(
        self, samples: Iterable[object], description: Optional[str], params: RuleGenParams
    ) -> GenericRule:
        ...

    async def refine_rule(
        self, existing_rule: GenericRule, feedback: str, samples: Optional[Iterable[object]] = None
    ) -> GenericRule:
        ...


class DummyRuleLLMClient:
    """Heuristic, offline rule generator."""

    async def generate_rule_from_description(
        self, description: str, logsource: Optional[LogSource], params: RuleGenParams
    ) -> GenericRule:
        desc = description.lower()
        if "powershell" in desc and ("encoded" in desc or "-enc" in desc or "base64" in desc):
            return self._powershell_encoded_rule(logsource)
        if "brute" in desc or "password spray" in desc or "failed login" in desc:
            return self._login_failure_rule(logsource)
        return self._keyword_match_rule(description, logsource)

    async def generate_rule_from_samples(
        self, samples: Iterable[object], description: Optional[str], params: RuleGenParams
    ) -> GenericRule:
        for sample in samples:
            event = getattr(sample, "parsed_event", None) or parse_event(getattr(sample, "raw_log", ""))
            if str(event.get("EventID")) == "4625":
                return self._login_failure_rule(None)
            cmd = str(event.get("CommandLine", "")).lower()
            if "powershell" in cmd and ("-enc" in cmd or "encodedcommand" in cmd):
                return self._powershell_encoded_rule(None)
        return self._keyword_match_rule(description or "sample derived rule", None)

    async def refine_rule(
        self, existing_rule: GenericRule, feedback: str, samples: Optional[Iterable[object]] = None
    ) -> GenericRule:
        refined = existing_rule.model_copy(deep=True)
        refined.tags.append("refined")
        if "less noisy" in feedback.lower() or "reduce false" in feedback.lower():
            refined.severity = refined.severity or "medium"
        return refined

    def _powershell_encoded_rule(self, logsource: Optional[LogSource]) -> GenericRule:
        return GenericRule(
            title="Suspicious Encoded PowerShell",
            description="Detect PowerShell executions using encoded commands.",
            logsource=logsource
            or LogSource(platform="windows", product="sysmon", service="process_creation", category="process_creation"),
            detection=DetectionBlock(
                selections={
                    "selection": {
                        "Image|endswith": "\\powershell.exe",
                        "CommandLine|contains": "-enc",
                    }
                },
                condition="selection",
            ),
            fields=["Image", "CommandLine", "User"],
            tags=["powershell", "encoded"],
            severity="high",
            mitre=["T1059.001"],
        )

    def _login_failure_rule(self, logsource: Optional[LogSource]) -> GenericRule:
        return GenericRule(
            title="Excessive Login Failures",
            description="Detect multiple login failures indicating possible password spraying.",
            logsource=logsource or LogSource(platform="windows", product="security"),
            detection=DetectionBlock(
                selections={
                    "failure": {"EventID|equals": 4625},
                },
                condition="failure",
            ),
            tags=["authentication", "password_spray"],
            severity="medium",
            mitre=["T1110"],
        )

    def _keyword_match_rule(self, description: str, logsource: Optional[LogSource]) -> GenericRule:
        keyword = description.split()[0] if description else "suspicious"
        return GenericRule(
            title=f"Keyword match for {keyword}",
            description=description or "Auto-generated keyword match.",
            logsource=logsource,
            detection=DetectionBlock(
                selections={"selection": {"message|contains": keyword}}, condition="selection"
            ),
            tags=["generic"],
            severity="low",
        )


class StubLLMClient:
    """Placeholder for a real LLM provider; does not perform network calls."""

    def __init__(self) -> None:
        self.provider = os.getenv("RULEGENIE_LLM_PROVIDER")
        self.api_key = os.getenv("RULEGENIE_LLM_API_KEY")

    async def generate_rule_from_description(
        self, description: str, logsource: Optional[LogSource], params: RuleGenParams
    ) -> GenericRule:
        raise NotImplementedError("Real LLM provider integration is not implemented in this stub.")

    async def generate_rule_from_samples(
        self, samples: Iterable[object], description: Optional[str], params: RuleGenParams
    ) -> GenericRule:
        raise NotImplementedError("Real LLM provider integration is not implemented in this stub.")

    async def refine_rule(
        self, existing_rule: GenericRule, feedback: str, samples: Optional[Iterable[object]] = None
    ) -> GenericRule:
        raise NotImplementedError("Real LLM provider integration is not implemented in this stub.")
