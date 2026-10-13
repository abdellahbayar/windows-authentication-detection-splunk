"""Offline checks of synthetic fixtures/configuration, not a Splunk execution test."""
import copy
import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from generate_data import SCENARIOS, detect_reference, generate

ROOT = Path(__file__).resolve().parent

def main():
    events = [json.loads(line) for line in (ROOT / "data/authentication.jsonl").read_text().splitlines()]
    assert len(events) == 55 and all(e["synthetic"] is True for e in events)
    assert len({(e["run_id"], e["Computer"], e["EventRecordID"]) for e in events}) == 55
    hits = detect_reference(events)
    assert [h["scenario_id"] for h in hits] == ["S01", "S08"]
    assert [h["window_seconds"] for h in hits] == [100, 280]
    assert all(h["failures_before_success"] == 5 for h in hits)
    positives = {h["scenario_id"] for h in hits}
    for sid, _, wanted in SCENARIOS: assert (sid in positives) == wanted, sid
    with (ROOT / "data/expected-detections.csv").open(newline="") as f:
        expected = list(csv.DictReader(f))
    assert [r["detection_id"] for r in expected] == [h["detection_id"] for h in hits]
    positive = [e for e in events if e["scenario_id"] == "S01"]
    assert len(detect_reference(positive + positive)) == 1, "duplicate records"
    assert not detect_reference(positive[1:]), "four failures must not trigger"
    case = copy.deepcopy(positive); case[-1]["TargetUserName"] = "LABUSER"
    assert len(detect_reference(case)) == 1, "case-insensitive target account"
    missing = copy.deepcopy(positive); missing[-1]["SourceIp"] = None
    assert not detect_reference(missing), "missing correlation key"
    domain = copy.deepcopy(positive); domain[-1]["TargetDomainName"] = "OTHER-DOMAIN"
    assert not detect_reference(domain), "different account namespace"
    query = (ROOT / "queries/03-detection.spl").read_text()
    assert "time_window=5m" in query and "current=f" in query
    assert "sort 0 +_time" in query and "failures_before_success>=5" in query
    assert "scenario_id=" not in query and "expected_alert" not in query
    app = ROOT / "app/abdellah_auth_lab"
    ET.parse(app / "default/data/ui/views/authentication_overview.xml")
    ET.parse(app / "default/data/ui/nav/default.xml")
    assert "disabled = 1" in (app / "default/savedsearches.conf").read_text()
    assert "KV_MODE = json" in (app / "default/props.conf").read_text()
    assert (app / "data/authentication.jsonl").read_bytes() == (ROOT / "data/authentication.jsonl").read_bytes()
    result = {"status": "PASS", "scope": "Offline Python reference and static checks; SPL has not been executed in Splunk",
              "fixture_events": len(events), "expected_hits": len(hits),
              "scenario_checks": 10, "additional_checks": ["dedup", "threshold", "account case", "missing key", "domain isolation", "XML/config"],
              "splunk_runtime_verified": False}
    (ROOT / "verification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))

if __name__ == "__main__": main()
