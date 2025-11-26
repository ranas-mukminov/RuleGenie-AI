import asyncio

from rulegenie.domain.ai_client import DummyRuleLLMClient, RuleGenParams
from rulegenie.domain.dsl import GenericRule


def test_dummy_llm_powershell():
    client = DummyRuleLLMClient()
    params = RuleGenParams(target_type="generic")
    rule: GenericRule = asyncio.run(
        client.generate_rule_from_description("Detect PowerShell encoded command", None, params)
    )
    assert any("CommandLine|contains" in k and "-enc" in str(v) for k, v in rule.detection.selections["selection"].items())
    assert rule.severity == "high"
