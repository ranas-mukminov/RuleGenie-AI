from types import SimpleNamespace

from rulegenie.domain.dsl import DetectionBlock, GenericRule
from rulegenie.domain.evaluation import run_evaluation


def test_evaluation_metrics():
    rule = GenericRule(
        title="Match EventID 1",
        detection=DetectionBlock(selections={"sel": {"EventID|equals": 1}}, condition="sel"),
    )
    events = [
        SimpleNamespace(raw_log='{"EventID": 1}', parsed_event={"EventID": 1}, is_malicious=True),
        SimpleNamespace(raw_log='{"EventID": 2}', parsed_event={"EventID": 2}, is_malicious=False),
        SimpleNamespace(raw_log='{"EventID": 1}', parsed_event={"EventID": 1}, is_malicious=False),
    ]
    metrics, details = run_evaluation(rule, events)
    assert metrics["tp"] == 1
    assert metrics["fp"] == 1
    assert metrics["fn"] == 0
    assert metrics["tn"] == 1
