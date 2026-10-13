# Synthetic authentication dataset

`authentication.jsonl` contains 55 generated JSON objects, one per line. These are normalized test records, not Windows XML, EVTX exports or records collected from the VMs. The CSV contains the same records for inspection; the app monitors only JSONL.

| Field | Meaning |
|---|---|
| timestamp | Synthetic UTC timestamp, ISO 8601 |
| EventCode | 4625 failure / 4624 success |
| EventRecordID | Synthetic identifier, unique per computer and run |
| Computer | Windows computer represented by the record |
| TargetDomainName | Namespace of the authentication target |
| TargetUserName | Account being authenticated |
| SubjectUserName | Requesting account, distinct from the target |
| SourceIp | Normalized IpAddress; ::1 represents loopback |
| LogonType | 2 interactive / 3 network |
| Status / SubStatus | Simulated diagnostic codes; not applicable to success |
| synthetic | Always true in generated fixtures |
| run_id | Separates test runs |
| scenario_id | Test label, not a detection condition |
| data_origin | generated_fixture_not_windows_export |

Names retained from the lab: DESKTOP-N7PEBGK, LabUser, LabAdmin and UtenteInesistente. The intended Splunk server is soc-mail-lab. WIN-LAB-02 is invented and 192.0.2.25 is an example address.

`expected-detections.csv` contains expected Python reference results, not an export from Splunk. `manifest.json` describes totals, scenarios and validation status.

The rule requires five preceding failures within 300 seconds before a success for the same correlation key. Positive fixtures span 100 and 280 seconds; exact boundary behavior is a separate runtime check.
