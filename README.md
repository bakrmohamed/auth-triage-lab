# Auth Triage Lab

An offline Python tool for turning a small authentication export into reviewable findings. Each finding includes the exact input lines, timestamps and events that caused it.

The focus is explainable SOC triage, not a risk score with no evidence. It runs without network access, credentials or third-party Python packages. All committed example events are synthetic.

## Try it

Python 3.10 or newer. From the repository directory:

```sh
python -m authtriage examples/auth-events.jsonl
python -m authtriage examples/auth-events.jsonl --format markdown
python -m unittest discover -s tests -v
```

The example produces **3 findings from 14 events**:

| Rule | Example evidence | What to check |
| --- | --- | --- |
| `repeated_failures` | Lines 3 to 7: five failures for `demo-admin` | Mistyped password, stale client credentials or guessing? |
| `success_after_failures` | Lines 3 to 8: those failures followed by a success | Was the success expected? Correlate MFA and session details. |
| `multi_user_failures` | Lines 9 to 13: five different users from one source | Shared gateway, test traffic or possible password spray? |

See [the generated example report](examples/report.md) and [the interview walkthrough](docs/WALKTHROUGH.md).

Save reports to new paths (existing files are never overwritten):

```sh
mkdir -p reports
python -m authtriage examples/auth-events.jsonl --output reports/triage.json
python -m authtriage examples/auth-events.jsonl --format markdown --output reports/triage.md
```

Optional installation, when a suitable setuptools build environment is available:

```sh
python -m pip install .
authtriage examples/auth-events.jsonl
```

Running from the checkout needs no installation. Installation may fetch build tooling; the triage commands themselves do not make network calls.

## Input contract

One UTF-8 JSON object per physical line:

```json
{"timestamp":"2026-11-01T08:00:00Z","source_ip":"192.0.2.10","user":"demo-admin","outcome":"failure","service":"ssh"}
```

- Required: `timestamp`, `source_ip`, `user`, `outcome`.
- `timestamp` must include a date, `T`, seconds, and `Z` or an explicit `+HH:MM`/`-HH:MM` offset. Fractional seconds up to six digits are accepted. Internal comparisons and reports use UTC.
- `source_ip` accepts IPv4 or IPv6, not a hostname or scoped IPv6 address.
- `outcome` is exactly `success` or `failure`.
- `user` and optional `service` are case-sensitive strings, stripped of surrounding whitespace, limited to 128 characters, with no ASCII control characters. Missing `service` becomes `unknown`.
- Unknown fields and duplicate JSON keys are rejected. Normalize raw logs first; this tool does not parse native SSH, Windows Event Log or vendor exports.
- Blank lines are skipped but still count toward physical line numbers and the input-line limit.
- Identical records are **not** deduplicated. An export containing duplicates can inflate counts.

Malformed records are skipped, with line numbers and safe reasons in `issues`. Raw malformed content is not echoed. For automation, use `--strict`: it still writes a report but exits with status `2` when any record was rejected. Without `--strict`, rejected rows are reported but do not change the successful exit status.

```sh
python -m authtriage examples/malformed.jsonl --strict
```

That fixture contains one valid event and three invalid records. It deliberately exits `2`.

## Rules and episode behavior

Events are sorted by timestamp, then physical input line for ties. Every window is inclusive: `[current_time - window, current_time]`.

| Rule | Grouping | Default trigger | Review label |
| --- | --- | --- | --- |
| `repeated_failures` | Source IP + user + service | 5 failures within 300 seconds | Medium |
| `multi_user_failures` | Source IP + service | Failures for 5 distinct users within 300 seconds | Medium |
| `success_after_failures` | Source IP + user + service | Success while at least 5 preceding failures remain in the window | High |

Review labels are fixed triage priorities, not calibrated probabilities.

The first two rules emit once when their window crosses from below to at/above threshold. They re-arm when that group's next event finds the window below threshold. They do not emit on every failure. A success closes the source/user/service failure episode; subsequent successes do not re-alert for those same failures. It does not clear the source's multi-user failure history.

Evidence contains **all matching failures in the window at the trigger**, plus the success for the success rule. A later event in an already-active episode is not silently appended to an earlier finding. The original log remains the source for full-session review.

Tune explicit thresholds rather than editing code:

```sh
python -m authtriage examples/auth-events.jsonl --window-seconds 120 --failure-threshold 3 --spray-users 4
```

Counts must be at least 2, and the window must be positive.

## Boundaries and tradeoffs

- A rule match is not proof of an attack. Shared IPs, password resets, retrying software and training labs can trigger these patterns.
- A success after failures is not proof that an account was compromised. The tool has no MFA, device, geolocation or session context.
- This is a batch learning/triage tool, not a SIEM, real-time monitor, blocking system or production detection service. There are no network probes or response actions.
- The same account attacked from several IPs and slow attempts outside the chosen window can be missed. Splitting an export into separate runs can miss patterns across file boundaries.
- Every run starts fresh. There is no persisted state, deduplication, allowlist or incremental ingestion.
- Sorting requires the valid events to fit in memory. Default limit: 200,000 physical lines and 65,536 characters per record. Use `--max-lines` to set a different positive line limit. A line-limit breach stops without a report; an oversized record is skipped as an input issue.
- Distinct-user sets are recalculated from each source's current window. Dense single-source input can be slower than evenly distributed input. Evidence-heavy reports can be large. Keep exports small and measure before raising limits.
- Reports deliberately retain usernames and source addresses for investigation. Do not commit real logs or generated real-data reports. Review sensitive data handling before using any workplace export.
- The output path uses exclusive creation. Existing output files, including the input file, are never overwritten. New output files use the process's filesystem permissions, so use a private directory for sensitive reports.

## Tests and layout

The test suite covers malformed input, timezone/IP normalization, exact window edges, out-of-order and tied events, episode suppression/re-arming, source/service isolation, escaped Markdown, output safety and CLI exit codes. A seeded randomized test also compares the deque-based rules against a separate simple history-scan implementation.

```text
authtriage/core.py       parsing, UTC normalization, rule state and evidence
authtriage/report.py     Markdown report rendering
authtriage/__main__.py   command-line boundary and output handling
tests/                  standard-library unittest tests
examples/               synthetic input and generated expected reports
docs/WALKTHROUGH.md     English and Egyptian Arabic interview notes
```

The workflow is configured to run tests on Python 3.10 through 3.13. A configured CI matrix is not a claim that every version has already been run locally. Local verification details are recorded in [docs/VERIFICATION.md](docs/VERIFICATION.md).

## Next useful steps

Add a well-tested adapter for one real log format, measure performance on larger synthetic batches, and compare thresholds against labeled benign and suspicious examples. Keep these separate from claims of production detection accuracy.

MIT licensed. No commercial incident data is included.
