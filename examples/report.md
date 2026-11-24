# Authentication triage report

Offline rule matches for analyst review. A match is not proof of an attack or account compromise.

Valid events: 14 | Invalid records: 0 | Findings: 3
Window: 300s, inclusive. Failure threshold: 5. Distinct-user threshold: 5.

## Findings

### A0001: repeated_failures (medium)

At least 5 failures for one source/user/service within 300s.

| Line | Timestamp (UTC) | Source | User | Service | Outcome |
| --- | --- | --- | --- | --- | --- |
| 3 | 2026-11-01T08:00:00Z | 192.0.2.10 | demo-admin | ssh | failure |
| 4 | 2026-11-01T08:01:00Z | 192.0.2.10 | demo-admin | ssh | failure |
| 5 | 2026-11-01T08:02:00Z | 192.0.2.10 | demo-admin | ssh | failure |
| 6 | 2026-11-01T08:03:00Z | 192.0.2.10 | demo-admin | ssh | failure |
| 7 | 2026-11-01T08:04:00Z | 192.0.2.10 | demo-admin | ssh | failure |

### A0002: success_after_failures (high)

Success after 5 failures for this source/user/service within 300s; verify whether expected.

| Line | Timestamp (UTC) | Source | User | Service | Outcome |
| --- | --- | --- | --- | --- | --- |
| 3 | 2026-11-01T08:00:00Z | 192.0.2.10 | demo-admin | ssh | failure |
| 4 | 2026-11-01T08:01:00Z | 192.0.2.10 | demo-admin | ssh | failure |
| 5 | 2026-11-01T08:02:00Z | 192.0.2.10 | demo-admin | ssh | failure |
| 6 | 2026-11-01T08:03:00Z | 192.0.2.10 | demo-admin | ssh | failure |
| 7 | 2026-11-01T08:04:00Z | 192.0.2.10 | demo-admin | ssh | failure |
| 8 | 2026-11-01T08:04:30Z | 192.0.2.10 | demo-admin | ssh | success |

### A0003: multi_user_failures (medium)

Failures against 5 distinct users from one source/service within 300s; possible spray pattern, not proof.

| Line | Timestamp (UTC) | Source | User | Service | Outcome |
| --- | --- | --- | --- | --- | --- |
| 9 | 2026-11-01T09:00:00Z | 198.51.100.20 | demo-alpha | vpn | failure |
| 10 | 2026-11-01T09:01:00Z | 198.51.100.20 | demo-bravo | vpn | failure |
| 11 | 2026-11-01T09:02:00Z | 198.51.100.20 | demo-charlie | vpn | failure |
| 12 | 2026-11-01T09:03:00Z | 198.51.100.20 | demo-delta | vpn | failure |
| 13 | 2026-11-01T09:04:00Z | 198.51.100.20 | demo-echo | vpn | failure |

## Input issues

None.

## Review before acting

- Check the source export and the referenced physical line numbers.
- Ask whether a shared IP, a service account or a client retry explains the activity.
- Correlate device, MFA and session evidence before concluding compromise.
- Treat reports as sensitive: they contain usernames and source addresses.
