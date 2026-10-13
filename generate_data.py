"""Generate explicitly synthetic Windows-like authentication records; no logons occur."""
import argparse
import csv
import json
import uuid
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

WINDOW = 300
THRESHOLD = 5
RUN_ID = "lab-auth-20261008"
HOST = "DESKTOP-N7PEBGK"
SCENARIOS = [
    ("S01", "Five failures, then success", True),
    ("S02", "One mistyped password, then success", False),
    ("S03", "Success precedes the failures", False),
    ("S04", "Success belongs to another account", False),
    ("S05", "Five failures spread beyond five minutes", False),
    ("S06", "Success has another source address", False),
    ("S07", "Success has another logon type", False),
    ("S08", "Five failures, success after 280 seconds", True),
    ("S09", "Unknown username, no success", False),
    ("S10", "Success belongs to another computer", False),
]

def generate():
    events = []
    base = datetime(2026, 10, 8, 9, tzinfo=timezone.utc)
    def add(scenario, offset, code, user="LabUser", ip="::1", logon=2, computer=HOST):
        stamp = base + timedelta(minutes=15 * (int(scenario[1:]) - 1), seconds=offset)
        events.append({
            "timestamp": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "EventCode": code, "EventRecordID": 42001 + len(events),
            "Computer": computer, "TargetDomainName": HOST,
            "TargetUserName": user, "SubjectUserName": "LabAdmin",
            "SourceIp": ip, "LogonType": logon,
            "Status": "0xC000006D" if code == 4625 else "not_applicable",
            "SubStatus": ("0xC0000064" if user == "UtenteInesistente" else "0xC000006A") if code == 4625 else "not_applicable",
            "synthetic": True, "run_id": RUN_ID, "scenario_id": scenario,
            "data_origin": "generated_fixture_not_windows_export",
        })
    for sid, _, _ in SCENARIOS:
        if sid == "S02":
            add(sid, 0, 4625); add(sid, 20, 4624)
        elif sid == "S03":
            add(sid, 0, 4624)
            for t in (20, 40, 60, 80, 100): add(sid, t, 4625)
        elif sid == "S05":
            for t in (0, 90, 180, 270, 360): add(sid, t, 4625)
            add(sid, 450, 4624)
        elif sid == "S08":
            for t in (0, 50, 100, 150, 200): add(sid, t, 4625)
            add(sid, 280, 4624)
        elif sid == "S09":
            for t in (0, 20, 40, 60, 80): add(sid, t, 4625, user="UtenteInesistente")
        else:
            for t in (0, 20, 40, 60, 80): add(sid, t, 4625, logon=3 if sid == "S07" else 2)
            add(sid, 100, 4624,
                user="LabAdmin" if sid == "S04" else "LabUser",
                ip="192.0.2.25" if sid == "S06" else "::1",
                computer="WIN-LAB-02" if sid == "S10" else HOST)
    return events

def epoch(event):
    return datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).timestamp()

def detect_reference(events):
    """Python reference for the documented window rule. This is NOT execution of SPL."""
    queues, seen, hits = defaultdict(deque), set(), []
    ordered = sorted(events, key=lambda e: (epoch(e), int(e["EventRecordID"])))
    for event in ordered:
        identity = (event.get("run_id"), event.get("Computer"), event.get("EventRecordID"))
        if identity in seen: continue
        seen.add(identity)
        required = ("run_id", "Computer", "TargetDomainName", "TargetUserName", "SourceIp", "LogonType")
        if any(event.get(k) in (None, "") for k in required): continue
        key = (event["run_id"], event["Computer"], event["TargetDomainName"].lower(),
               event["TargetUserName"].lower(), event["SourceIp"], int(event["LogonType"]))
        t, q = epoch(event), queues[key]
        while q and t - q[0] > WINDOW: q.popleft()
        if int(event["EventCode"]) == 4624 and len(q) >= THRESHOLD:
            hits.append({"detection_id": f'{event["run_id"]}:{event["Computer"]}:{event["EventRecordID"]}',
                         "scenario_id": event["scenario_id"], "Computer": event["Computer"],
                         "TargetUserName": event["TargetUserName"], "SourceIp": event["SourceIp"],
                         "LogonType": event["LogonType"], "success_time": event["timestamp"],
                         "success_epoch": t, "first_failure_epoch": q[0],
                         "failures_before_success": len(q), "window_seconds": int(t - q[0]),
                         "EventRecordID": event["EventRecordID"], "synthetic": True})
        if int(event["EventCode"]) == 4625: q.append(t)
    return hits

def write_data(output):
    output = Path(output); output.mkdir(parents=True, exist_ok=True)
    events = generate(); hits = detect_reference(events)
    (output / "authentication.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    with (output / "authentication.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(events[0])); writer.writeheader(); writer.writerows(events)
    with (output / "expected-detections.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(hits[0])); writer.writeheader(); writer.writerows(hits)
    stats = {"synthetic": True, "splunk_execution_verified": False, "run_id": RUN_ID,
             "events": len(events), "failures": sum(e["EventCode"] == 4625 for e in events),
             "successes": sum(e["EventCode"] == 4624 for e in events), "expected_detections": len(hits),
             "by_scenario": dict(Counter(e["scenario_id"] for e in events)),
             "expected_positive_scenarios": ["S01", "S08"],
             "scenarios": [{"id": s, "description": d, "expected_alert": p} for s, d, p in SCENARIOS]}
    (output / "manifest.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    return events, hits, stats

def write_live(output):
    """Six synthetic records dated in the last two minutes, for one scheduled-alert check."""
    path = Path(output)
    if path.exists(): raise SystemExit("Choose a new file: refusing to overwrite an ingested fixture.")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    run = "lab-auth-live-" + now.strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    events = [e.copy() for e in generate() if e["scenario_id"] == "S01"]
    for i, event in enumerate(events):
        event["timestamp"] = (now - timedelta(seconds=120 - i * 20)).strftime("%Y-%m-%dT%H:%M:%SZ")
        event["run_id"] = run
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    print(f"Created {path}: 6 SYNTHETIC events, run_id={run}. No Windows logons performed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="data")
    parser.add_argument("--live-positive", metavar="NEW_JSONL_FILE")
    args = parser.parse_args()
    if args.live_positive: write_live(args.live_positive)
    else:
        _, _, stats = write_data(args.output)
        print(json.dumps(stats, indent=2))
