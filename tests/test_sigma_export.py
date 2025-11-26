from rulegenie.domain.dsl import DetectionBlock, GenericRule, LogSource
from rulegenie.domain.sigma_export import generic_rule_to_pseudo_query, generic_rule_to_sigma


def sample_rule() -> GenericRule:
    return GenericRule(
        title="Suspicious Encoded PowerShell",
        description="Detect encoded PowerShell commands",
        logsource=LogSource(platform="windows", product="sysmon"),
        detection=DetectionBlock(
            selections={
                "selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-enc"},
                "filter": {"User|equals": "SYSTEM"},
            },
            condition="selection and not filter",
        ),
        fields=["Image", "CommandLine"],
        severity="high",
        tags=["powershell"],
    )


def test_sigma_export_contains_expected_keys():
    sigma = generic_rule_to_sigma(sample_rule())
    assert "title: Suspicious Encoded PowerShell" in sigma
    assert "detection:" in sigma
    assert "condition: selection and not filter" in sigma


def test_pseudo_query_renders_condition():
    query = generic_rule_to_pseudo_query(sample_rule())
    assert "AND" in query
    assert "powershell.exe" in query
