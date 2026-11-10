import json

import pytest
from pydantic import ValidationError

from src.ingestion.models import CloudTrailRecord, load_events, normalize


def make_raw(**changes):
    raw = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/bob",
            "accountId": "123456789012",
            "userName": "bob",
        },
        "eventTime": "2026-11-10T10:25:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.11",
        "userAgent": "aws-cli/2.15.0",
        "requestParameters": {
            "userName": "bob",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
        "responseElements": None,
        "eventID": "e-1",
        "eventType": "AwsApiCall",
    }
    raw.update(changes)
    return raw


def test_normalize_basic_fields():
    event = normalize(CloudTrailRecord.model_validate(make_raw()))
    assert event.event_id == "e-1"
    assert event.event_time == "2026-11-10T10:25:00Z"
    assert event.identity_name == "bob"
    assert event.source_ip == "203.0.113.11"
    assert event.mfa_used is None
    assert event.login_result is None
    assert "AdministratorAccess" in event.request_params


def test_missing_required_field_is_rejected():
    raw = make_raw()
    del raw["eventName"]
    with pytest.raises(ValidationError):
        CloudTrailRecord.model_validate(raw)


def test_console_login_failure_without_mfa():
    raw = make_raw(
        eventName="ConsoleLogin",
        eventSource="signin.amazonaws.com",
        requestParameters=None,
        responseElements={"ConsoleLogin": "Failure"},
        additionalEventData={"MFAUsed": "No"},
    )
    event = normalize(CloudTrailRecord.model_validate(raw))
    assert event.login_result == "Failure"
    assert event.mfa_used == 0


def test_load_events_separates_valid_and_rejected(tmp_path):
    bad = make_raw(eventID="e-2")
    del bad["awsRegion"]
    logs = tmp_path / "logs.json"
    logs.write_text(json.dumps({"Records": [make_raw(), bad]}), encoding="utf-8")
    labels = tmp_path / "labels.csv"
    labels.write_text("eventID,scenario,is_attack\ne-1,privilege_escalation,1\n", encoding="utf-8")

    events, rejected = load_events(logs, labels)

    assert len(events) == 1
    assert events[0].scenario == "privilege_escalation"
    assert events[0].is_attack == 1
    assert len(rejected) == 1
    assert rejected[0]["eventID"] == "e-2"
