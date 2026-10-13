# Synthetic authentication detection analysis

Author: Abdellah Bayar | Prepared: 12 October 2026

**Synthetic exercise. No incident and no Splunk runtime execution are asserted.**

## Objective
Detect five failed authentications followed by a success within a rolling five-minute window.

## Dataset
55 generated records (46 failures, 9 successes),
run `lab-auth-20261008`. Host/account names reflect the existing lab, not production telemetry.

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
