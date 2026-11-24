# Verification record

Local verification used Python 3.10.12 on Linux. Commands were run from a clean project checkout directory; no account login or private dataset was involved.

- `python -m unittest discover -s tests -v`: **29 tests passed**.
- The randomized-reference test checks 30 seeded batches of 60 synthetic events against a separate history-scan model.
- `python -m compileall -q authtriage tests`: completed.
- `python -m authtriage examples/auth-events.jsonl --strict`: exit 0, 14 valid events, 3 findings, no invalid records.
- Committed JSON and Markdown example reports are checked byte-for-byte by a CLI regression test.
- `python -m authtriage examples/malformed.jsonl --strict`: exit 2, one valid event and three rejected records, report still produced.
- `python -m pip wheel . --no-deps --no-build-isolation`: produced `auth_triage_lab-0.1.0-py3-none-any.whl` with the expected package and entry point.
- Installed that wheel in a separate local virtual environment. Ran its `authtriage` entry point from outside the source tree; its synthetic JSON output exactly matched the committed example.
- README and generated Markdown report were rendered in a local browser and visually inspected for headings, tables, code blocks and evidence legibility. This is not verification of GitHub's final rendering.

Python 3.11, 3.12 and 3.13 were not available locally for execution. The CI workflow is configured for 3.10 through 3.13, but its remote results must be checked after publication. There is no measured detection-accuracy, production-performance or zero-defect claim.

## Captured unittest output

```text
test_bad_config_and_missing_file (test_cli.CliTests) ... ok
test_committed_example_reports_are_reproducible (test_cli.CliTests) ... ok
test_input_cannot_be_overwritten (test_cli.CliTests) ... ok
test_invalid_utf8 (test_cli.CliTests) ... ok
test_malformed_fixture (test_cli.CliTests) ... ok
test_output_and_no_overwrite (test_cli.CliTests) ... ok
test_permissive_reports_invalid (test_cli.CliTests) ... ok
test_stdin (test_cli.CliTests) ... ok
test_strict_still_emits_report (test_cli.CliTests) ... ok
test_distinct_users_not_failure_count (test_core.DetectionTests) ... ok
test_empty_is_valid (test_core.DetectionTests) ... ok
test_extreme_supported_date (test_core.DetectionTests) ... ok
test_inclusive_boundary_and_success_evidence (test_core.DetectionTests) ... ok
test_ip_service_and_user_isolation (test_core.DetectionTests) ... ok
test_markdown_escapes_untrusted_labels (test_core.DetectionTests) ... ok
test_one_alert_per_active_burst_then_rearms (test_core.DetectionTests) ... ok
test_outside_window_does_not_match (test_core.DetectionTests) ... ok
test_randomized_rules_against_simple_reference (test_core.DetectionTests) ... ok
test_repeat_runs_deterministic (test_core.DetectionTests) ... ok
test_sort_out_of_order_input (test_core.DetectionTests) ... ok
test_success_closes_pair_episode (test_core.DetectionTests) ... ok
test_success_does_not_clear_spray_history (test_core.DetectionTests) ... ok
test_tied_times_follow_physical_line_order (test_core.DetectionTests) ... ok
test_default_service_and_trimmed_user (test_core.ParserTests) ... ok
test_issues_keep_physical_lines_and_hide_content (test_core.ParserTests) ... ok
test_line_limit_and_config (test_core.ParserTests) ... ok
test_offsets_and_ipv6_normalize (test_core.ParserTests) ... ok
test_oversized_record_is_one_issue_then_recovers (test_core.ParserTests) ... ok
test_rejects_bad_schema (test_core.ParserTests) ... ok

----------------------------------------------------------------------
Ran 29 tests in 0.596s

OK
```
