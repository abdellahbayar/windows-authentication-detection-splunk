"""Build the reproducible synthetic Splunk lab and its documentation assets."""
import html
import json
import shutil
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path
from generate_data import RUN_ID, SCENARIOS, write_data

ROOT = Path(__file__).resolve().parent
APP = ROOT / "app/abdellah_auth_lab"
BASE = f'index=lab_windows_auth sourcetype="lab:windows:auth:json" synthetic=true run_id="{RUN_ID}"'
PREFIX = '''| eval EventCode=tonumber(EventCode), LogonType=tonumber(LogonType), target_user=lower(TargetUserName), target_domain=lower(TargetDomainName)
| where isnotnull(Computer) AND isnotnull(target_user) AND isnotnull(target_domain) AND isnotnull(SourceIp) AND SourceIp!="" AND SourceIp!="-" AND isnotnull(LogonType)
| dedup run_id Computer EventRecordID
| sort 0 +_time +EventRecordID
| streamstats current=f time_window=5m count(eval(EventCode=4625)) AS failures_before_success min(eval(if(EventCode=4625,_time,null()))) AS first_failure BY run_id Computer target_domain target_user SourceIp LogonType
| where EventCode=4624 AND failures_before_success>=5
| eval success_epoch=_time, window_seconds=round(_time-first_failure,0), detection_id=run_id.":".Computer.":".EventRecordID'''
TABLE = '| table _time first_failure Computer TargetDomainName TargetUserName SourceIp LogonType failures_before_success window_seconds EventRecordID detection_id scenario_id run_id'
DETECTION = BASE + ' (EventCode=4624 OR EventCode=4625)\n' + PREFIX + '\n' + TABLE
LIVE = 'index=lab_windows_auth sourcetype="lab:windows:auth:json" synthetic=true run_id="lab-auth-live-*" (EventCode=4624 OR EventCode=4625)\n' + PREFIX + '\n| where success_epoch>=relative_time(now(),"-2m@m") AND success_epoch<relative_time(now(),"-1m@m")\n' + TABLE
QUERIES = {
    "01-ingestion.spl": BASE + '\n| stats count AS events count(eval(EventCode=4625)) AS failures count(eval(EventCode=4624)) AS successes dc(EventRecordID) AS record_ids',
    "02-timeline.spl": BASE + '\n| sort 0 +_time +EventRecordID\n| table _time Computer TargetUserName SubjectUserName EventCode SourceIp LogonType SubStatus EventRecordID scenario_id',
    "03-detection.spl": DETECTION,
    "04-scenarios.spl": BASE + '\n| stats count AS events count(eval(EventCode=4625)) AS failures count(eval(EventCode=4624)) AS successes BY scenario_id\n| sort scenario_id',
    "05-substatus.spl": BASE + ' EventCode=4625\n| stats count BY TargetUserName SubStatus\n| sort -count',
    "06-live-alert.spl": LIVE,
    "07-triage-s01.spl": BASE + ' scenario_id=S01\n| sort 0 +_time +EventRecordID\n| table _time EventCode TargetUserName SubjectUserName Computer SourceIp LogonType SubStatus EventRecordID',
    "08-data-quality.spl": BASE + '\n| eval missing_key=if(isnull(Computer) OR isnull(TargetUserName) OR isnull(TargetDomainName) OR isnull(SourceIp) OR SourceIp="-" OR isnull(LogonType),1,0)\n| stats count AS events sum(missing_key) AS events_missing_key dc(run_id) AS runs',
}

SOURCES = [
    ("Splunk Enterprise download", "https://www.splunk.com/en_us/download/splunk-enterprise.html"),
    ("Linux installation", "https://help.splunk.com/en/splunk-enterprise/administer/install-and-upgrade/10.6/install-splunk-enterprise-on-linux-or-macos/install-on-linux"),
    ("Run Splunk as a non-root user", "https://help.splunk.com/en/splunk-enterprise/administer/install-and-upgrade/10.6/install-splunk-enterprise-on-linux-or-macos/run-splunk-enterprise-as-a-different-or-non-root-user"),
    ("SPL streamstats", "https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.3/search-commands/streamstats"),
    ("props.conf reference", "https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.3/configuration-file-reference/9.3.0-configuration-file-reference/props.conf"),
    ("savedsearches.conf reference", "https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.8-configuration-file-reference/savedsearches.conf"),
    ("Microsoft: event 4624", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624"),
    ("Microsoft: event 4625", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625"),
]

def write(path, value):
    path = ROOT / path; path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.rstrip() + '\n', encoding="utf-8")

def build_app(events):
    default = APP / "default"; default.mkdir(parents=True, exist_ok=True)
    write(default / "app.conf", '''[install]
is_configured = 1
[ui]
is_visible = 1
label = Abdellah Authentication Lab (Synthetic)
[launcher]
author = Abdellah Bayar
description = Reproducible synthetic authentication detection lab. Runtime validation pending.
version = 1.0.0
''')
    write(default / "indexes.conf", '''[lab_windows_auth]
homePath = $SPLUNK_DB/lab_windows_auth/db
coldPath = $SPLUNK_DB/lab_windows_auth/colddb
thawedPath = $SPLUNK_DB/lab_windows_auth/thaweddb
maxTotalDataSizeMB = 256
frozenTimePeriodInSecs = 31536000
''')
    write(default / "props.conf", r'''[lab:windows:auth:json]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "timestamp":\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%SZ
MAX_TIMESTAMP_LOOKAHEAD = 20
TZ = UTC
KV_MODE = json
TRUNCATE = 10000
''')
    write(default / "inputs.conf", r'''[monitor:///opt/splunk/etc/apps/abdellah_auth_lab/data]
disabled = 0
whitelist = \.jsonl$
index = lab_windows_auth
sourcetype = lab:windows:auth:json
host = synthetic-fixture
''')
    write(APP / "metadata/default.meta", '''[]
access = read : [ * ], write : [ admin ]
export = none
''')
    write(default / "savedsearches.conf", '[LAB - Historical detection (synthetic)]\nsearch = ' + DETECTION.replace('\n', ' ') + '''
enableSched = 0
dispatch.earliest_time = 0
dispatch.latest_time = now

[LAB - Live synthetic alert]
description = Disabled by default. Six generated JSON events test scheduling; no Windows logons are performed.
search = ''' + LIVE.replace('\n', ' ') + '''
disabled = 1
enableSched = 1
cron_schedule = * * * * *
dispatch.earliest_time = -7m@m
dispatch.latest_time = -1m@m
counttype = number of events
relation = greater than
quantity = 0
alert.track = true
alert.digest_mode = false
alert.expires = 24h
alert.suppress = 1
alert.suppress.period = 10m
alert.suppress.fields = detection_id
''')
    dashboard = ET.Element("dashboard", {"version": "1.1", "theme": "dark"})
    ET.SubElement(dashboard, "label").text = "Windows Authentication | SYNTHETIC LAB"
    ET.SubElement(dashboard, "description").text = "55 generated records; expected results, not production incidents. UTC recommended. Fixed historical run."
    row = ET.SubElement(dashboard, "row")
    for title, query in [
        ("Synthetic events (expected: 55)", BASE + " | stats count"),
        ("Failed logons (expected: 46)", BASE + " EventCode=4625 | stats count"),
        ("Successful logons (expected: 9)", BASE + " EventCode=4624 | stats count"),
        ("Detection matches (expected: 2)", DETECTION + " | stats count"),
    ]:
        panel = ET.SubElement(row, "panel"); ET.SubElement(panel, "title").text = title
        single = ET.SubElement(panel, "single"); search = ET.SubElement(single, "search")
        ET.SubElement(search, "query").text = query
        ET.SubElement(search, "earliest").text = "0"; ET.SubElement(search, "latest").text = "now"
    for title, kind, query in [
        ("Authentication timeline", "chart", BASE + " | timechart span=5m count BY EventCode"),
        ("Candidates for triage", "table", DETECTION),
        ("Scenario coverage", "table", QUERIES["04-scenarios.spl"]),
    ]:
        row = ET.SubElement(dashboard, "row"); panel = ET.SubElement(row, "panel")
        ET.SubElement(panel, "title").text = title; vis = ET.SubElement(panel, kind)
        search = ET.SubElement(vis, "search"); ET.SubElement(search, "query").text = query
        ET.SubElement(search, "earliest").text = "0"; ET.SubElement(search, "latest").text = "now"
        if kind == "chart": ET.SubElement(vis, "option", {"name": "charting.chart"}).text = "column"
    xml_path = default / "data/ui/views/authentication_overview.xml"; xml_path.parent.mkdir(parents=True, exist_ok=True)
    ET.indent(dashboard); ET.ElementTree(dashboard).write(xml_path, encoding="utf-8", xml_declaration=True)
    write(default / "data/ui/nav/default.xml", '<nav search_view="search"><view name="authentication_overview" default="true"/><view name="search"/><view name="alerts"/></nav>')
    (APP / "data").mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "data/authentication.jsonl", APP / "data/authentication.jsonl")
    with tarfile.open(ROOT / "abdellah_auth_lab.tar.gz", "w:gz") as archive:
        archive.add(APP, arcname="abdellah_auth_lab")

def chapters(stats, hits):
    return json.loads((ROOT / "guide-content.json").read_text(encoding="utf-8"))


def build_documents(stats, hits):
    pages = chapters(stats, hits)
    write("chapters.json", json.dumps(pages, ensure_ascii=False, indent=2))
    md = ["# Complete Guide - Windows Authentication Detection with Splunk", "", "**Synthetic dataset. Splunk search and alert runtime validation is pending.**", ""]
    for page in pages:
        md += ["## " + page["title"], ""]
        for p in page.get("paragraphs", []): md += [p, ""]
        for b in page.get("bullets", []): md.append("- " + b)
        if page.get("bullets"): md.append("")
        if page.get("code"): md += ["```text", page["code"], "```", ""]
        if page.get("screen"): md += [f'![Illustrative preview](screenshots/{page["screen"]}.png)', ""]
        if page.get("image"): md += [f'![Original Ubuntu preparation capture](screenshots/{page["image"]})', ""]
        for title, url in page.get("links", []): md += [f"- [{title}]({url})"]
    write("GUIDE.md", "\n".join(md))
    write("README.md", f'''# Windows Authentication Detection with Splunk

A reproducible **synthetic-data detection lab** by Abdellah Bayar.

## Scope and verification

55 generated Windows-like authentication records; 10 scenarios; 2 expected detection matches.
The fixtures reuse the lab names `DESKTOP-N7PEBGK`, `LabUser`, `LabAdmin` and `soc-mail-lab`.
`WIN-LAB-02` is invented. These are normalized JSON records, **not EVTX exports**.
The main lab does not require a Universal Forwarder and performs no Windows logons.

The data and Python reference model have offline checks. **SPL, dashboard and scheduled alert have not been runtime-verified in Splunk.**
Illustrative screenshots are captures of the bundled local demonstrator, visibly marked as simulated.
The original Ubuntu prerequisite screenshots document only machine preparation.

## Reports

- [Analysis report](docs/Windows-Authentication-Splunk-Analysis-Abdellah-Bayar.pdf)
- [Reproduction guide](docs/Windows-Authentication-Detection-with-Splunk.pdf)

## Start here

1. Read [the step-by-step guide](GUIDE.md).
2. Open [the interactive offline demonstrator](preview/index.html).
3. Install Splunk Enterprise in the Ubuntu lab VM, then install `abdellah_auth_lab.tar.gz` using the guide.
4. Compare search output with `data/expected-detections.csv`.
5. Validate the disabled-by-default live alert using a newly generated synthetic fixture.
6. Record actual results in `report/actual-validation-template.md`.

## Detection

At each successful authentication, count at least five preceding failures within five minutes
for the same run, computer, target domain, target account, source address and logon type.
Sort chronologically; do not treat a preceding success as confirmation of later failures.
An alert is a candidate for investigation, **not proof of compromise**.

## Files

- `app/abdellah_auth_lab/`: index, JSON parsing, monitor input, Simple XML dashboard and saved searches.
- `queries/`: 8 copyable SPL searches, including timeline, detection, triage and data-quality checks.
- `data/`: deterministic JSONL/CSV fixtures, manifest and expected detection output.
- `generate_data.py`: historical dataset or a six-event current-time alert fixture; Python standard library only.
- `verify_project.py`: offline semantic and static checks; Python standard library only.
- `report/`: synthetic analysis, expected test matrix and actual-validation template.
- `optional/`: normalized export script for selected real lab events; no audit/account changes.
- `screenshots/`: labeled illustrations plus original Ubuntu screenshots.

## Offline verification

```bash
python3 verify_project.py
```

## Live synthetic fixture

```bash
python3 generate_data.py --live-positive authentication-live-01.jsonl
```

This generates six records dated within the preceding two minutes. Each fixture has a distinct `run_id`.
It does not perform authentication, contact accounts, or interact with Windows.
Do not upload the same historical file twice. Use a new filename for every live test.

## Limitations

Small-data SPL uses `sort 0`; this is not a production-scale detection design.
The alert schedule assumes ingestion latency under one minute; tune overlap/delay for real telemetry.
Source-address or logon-type changes can produce false negatives. Missing keys are excluded.
Repeated successful events can produce multiple candidates with separate detection IDs.
The fixture does not model password spraying, distributed attacks, remote identity attribution,
EDR containment or Enterprise Security incident management.

## Sources

See the final chapter of the guide. Local files contain no credentials. No repository has been published.
''')
    write("report/analysis.md", f'''# Synthetic authentication detection analysis

Author: Abdellah Bayar | Prepared: 12 October 2026

**Synthetic exercise. No incident and no Splunk runtime execution are asserted.**

## Objective
Detect five failed authentications followed by a success within a rolling five-minute window.

## Dataset
{stats['events']} generated records ({stats['failures']} failures, {stats['successes']} successes),
run `{RUN_ID}`. Host/account names reflect the existing lab, not production telemetry.

## Expected findings
S01: five failures, then success at 09:01:40 UTC, 100 seconds after the first failure.
S08: five failures, then success at 10:49:40 UTC, 280 seconds after the first failure.
Both concern LabUser on DESKTOP-N7PEBGK, source ::1 and logon type 2.
All other scenarios should have no matches. See `test-matrix.csv`.

## Interpretation
The pattern is observable in the fixture. It could also occur during manual retries or administrative testing.
The generator explains the activity here; no real compromise is demonstrated.
SubjectUserName identifies the requester and TargetUserName identifies the authentication target.
The IP of soc-mail-lab is not the source of the simulated Windows logons.

## Investigation plan for real telemetry
Confirm the operator/test context; preserve the original events; inspect calling process, logon/session
identifiers and post-logon activity; search other hosts/accounts; verify audit coverage and ingestion latency.
Use established escalation procedures for a critical notification; containment requires team authorization.

## Verification
Python reference logic and static configuration checks are recorded in `../verification.json`.
These checks do not execute SPL and do not prove that Splunk parsed the file correctly.
Record actual query results, version/license and screenshots using `actual-validation-template.md`.

## Practical limits
The synthetic fields are normalized; native Windows add-ons can expose different names.
Strict source/type correlation can miss sequences that change either key.
The job excludes missing keys and assumes limited delay. The threshold is educational.
Exactly 300-second boundary behavior must be checked in Splunk; the positive fixtures avoid that boundary.
''')
    write("report/actual-validation-template.md", '''# Actual Splunk validation - to complete

Status: Runtime validation pending.

- Execution date/time and timezone:
- Splunk version and active license:
- Ubuntu hostname and IP at execution:
- Installation/import method:
- Dataset run_id and SHA256:
- Ingestion count / failures / successes / unique records:
- Detection result IDs compared with expected-detections.csv:
- All ten scenario results:
- Actual screenshot filenames (UI, filters and results visible):
- Scheduled job SID, live fixture run_id and Triggered Alerts result:
- Missing fields, warnings, latency and errors:
- Changes made to query/configuration:
- Final conclusion and remaining limits:

Keep passwords, tokens and personal/production logs out of this report.
''')
    import csv
    with (ROOT / "report/test-matrix.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["scenario_id", "description", "expected_matches", "reference_matches", "splunk_actual_matches"])
        for sid, desc, positive in SCENARIOS:
            w.writerow([sid, desc, int(positive), sum(h["scenario_id"] == sid for h in hits), "NOT_EXECUTED"])
    write("evidence/actual-splunk/README.md", "Place actual Splunk screenshots and exported search results here. Keep the search, time filter, run_id and results visible in each capture.")
    write("optional/export_lab_events.ps1", '''param(
    [Parameter(Mandatory=$true)][datetime]$StartTime,
    [Parameter(Mandatory=$true)][datetime]$EndTime,
    [string]$OutputPath = '.\\windows-real.jsonl'
)
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne 'DESKTOP-N7PEBGK') { throw 'Run only inside the documented Windows lab VM.' }
if ($EndTime -le $StartTime) { throw 'EndTime must follow StartTime.' }
if (Test-Path -LiteralPath $OutputPath) { throw 'Choose a new output filename.' }
$runId = 'windows-real-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$lines = @()
$records = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=$StartTime; EndTime=$EndTime}
foreach ($record in ($records | Sort-Object TimeCreated, RecordId)) {
    [xml]$xml = $record.ToXml()
    $fields = @{}
    foreach ($node in $xml.Event.EventData.Data) { $fields[$node.GetAttribute('Name')] = $node.InnerText }
    if ($fields['TargetUserName'] -notin @('LabUser','LabAdmin','UtenteInesistente')) { continue }
    $row = [ordered]@{
        timestamp=$record.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        EventCode=$record.Id; EventRecordID=$record.RecordId; Computer=$record.MachineName
        TargetDomainName=$fields['TargetDomainName']; TargetUserName=$fields['TargetUserName']
        SubjectUserName=$fields['SubjectUserName']; SourceIp=$fields['IpAddress']
        LogonType=$fields['LogonType']; Status=$fields['Status']; SubStatus=$fields['SubStatus']
        synthetic=$false; run_id=$runId; scenario_id='actual_lab'
        data_origin='normalized_from_windows_security_log'
    }
    $lines += ($row | ConvertTo-Json -Compress)
}
if ($lines.Count -eq 0) { throw 'No selected lab-account events in this interval.' }
[System.IO.File]::WriteAllLines([System.IO.Path]::GetFullPath($OutputPath), [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))
Write-Output "Exported $($lines.Count) REAL lab records, run_id=$runId. Original EVTX should be preserved separately."
''')
    return pages

def main():
    events, hits, stats = write_data(ROOT / "data")
    for name, query in QUERIES.items(): write("queries/" + name, query)
    build_app(events); pages = build_documents(stats, hits)
    shots = ROOT / "screenshots"; shots.mkdir(parents=True, exist_ok=True)
    write("preview/payload.json", json.dumps({"events": events, "hits": hits, "stats": stats, "query": DETECTION}, ensure_ascii=False))
    print(json.dumps({"project": str(ROOT), "events": stats["events"], "expected_hits": len(hits), "chapters": len(pages)}))

if __name__ == "__main__": main()
