import pytest

from rulegenie.domain.dsl import DetectionBlock, GenericRule, LogSource


def test_generic_rule_validation_passes():
    rule = GenericRule(
        title="Test Rule",
        description="Simple test rule",
        logsource=LogSource(platform="windows", product="sysmon"),
        detection=DetectionBlock(selections={"sel1": {"EventID|equals": 1}}, condition="sel1"),
    )
    assert rule.detection.condition == "sel1"


def test_generic_rule_missing_selection_raises():
    with pytest.raises(ValueError):
        GenericRule(
            title="Bad Rule",
            detection=DetectionBlock(selections={"sel1": {"field": "value"}}, condition="sel2"),
        )
