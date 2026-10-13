# Windows Authentication Detection with Splunk

A reproducible **synthetic-data detection lab** by Abdellah Bayar.

[Analysis report](docs/Windows-Authentication-Splunk-Analysis-Abdellah-Bayar.pdf) · [Reproduction guide](docs/Windows-Authentication-Detection-with-Splunk.pdf) · [Portfolio project page](https://abdellahbayar.com/en/projects/windows-authentication-detection-splunk/)

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
