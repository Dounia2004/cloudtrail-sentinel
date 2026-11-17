from src.detection.alerts import build_alert
from src.detection.engine import run_rules
from src.evaluation.rules_eval import TARGET_RULES, evaluate, format_markdown, format_text


def test_overall_on_fixtures_has_no_false_positive(fixture_events):
    result = evaluate(fixture_events, run_rules(fixture_events))
    assert result.overall.fp == 0
    assert result.overall.precision == 1.0
    assert result.overall.recall > 0.9


def test_every_scenario_is_detected_by_its_target_rules(fixture_events):
    result = evaluate(fixture_events, run_rules(fixture_events))
    assert {s.scenario for s in result.scenarios} == set(TARGET_RULES)
    for scenario in result.scenarios:
        assert scenario.detected, scenario.scenario
        assert scenario.targets_fired == scenario.targets, scenario.scenario


def test_all_twelve_rules_are_reported(fixture_events):
    result = evaluate(fixture_events, run_rules(fixture_events))
    assert len(result.rules) == 12
    silent = {r.rule_id for r in result.rules if r.alerts == 0}
    assert silent == {"IAM-002", "IAM-003", "AUTH-004"}
    assert all(r.precision is None for r in result.rules if r.rule_id in silent)


def test_metrics_with_known_counts(make_event):
    attack_hit = make_event(event_id="a1", is_attack=1, scenario="iam_recon")
    attack_missed = make_event(event_id="a2", is_attack=1, scenario="iam_recon")
    normal_hit = make_event(event_id="n1", is_attack=0, scenario="normal")
    normal_ok = make_event(event_id="n2", is_attack=0, scenario="normal")
    alerts = [
        build_alert("IAM-006", "T1087.004", "medium", [attack_hit], "vraie alerte"),
        build_alert("IAM-001", "T1098", "high", [normal_hit], "fausse alerte"),
    ]
    result = evaluate(
        [attack_hit, attack_missed, normal_hit, normal_ok], alerts, ["IAM-006", "IAM-001"]
    )
    overall = result.overall
    assert (overall.tp, overall.fp, overall.fn) == (1, 1, 1)
    assert overall.precision == 0.5
    assert overall.recall == 0.5
    assert overall.f1 == 0.5
    by_rule = {r.rule_id: r for r in result.rules}
    assert by_rule["IAM-006"].true_alerts == 1
    assert by_rule["IAM-001"].false_alerts == 1
    assert by_rule["IAM-001"].precision == 0.0
    assert result.scenarios[0].flagged == 1
    assert result.scenarios[0].recall == 0.5


def test_reports_are_formatted(fixture_events):
    result = evaluate(fixture_events, run_rules(fixture_events))
    text = format_text(result)
    assert "IAM-001" in text and "credential_abuse" in text
    markdown = format_markdown(result)
    assert markdown.startswith("# Évaluation")
    assert "| Règle |" in markdown
