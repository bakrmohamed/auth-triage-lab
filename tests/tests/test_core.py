import io
import json
import random
import unittest
from datetime import datetime, timedelta, timezone

from authtriage.core import Config, analyze, parse_event, read_events
from authtriage.report import markdown


BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def record(second=0, user="demo", outcome="failure", ip="192.0.2.10", service="ssh"):
    return dict(timestamp=(BASE + timedelta(seconds=second)).isoformat(), source_ip=ip,
                user=user, outcome=outcome, service=service)


def events(records):
    return [parse_event(json.dumps(row), line) for line, row in enumerate(records, 1)]


class ParserTests(unittest.TestCase):
    def test_offsets_and_ipv6_normalize(self):
        row = record(ip="2001:0db8:0:0::1")
        row["timestamp"] = "2026-01-01T02:00:00+02:00"
        parsed = parse_event(json.dumps(row), 4)
        self.assertEqual(parsed.timestamp, BASE)
        self.assertEqual(parsed.source_ip, "2001:db8::1")
        self.assertEqual(parsed.line, 4)

    def test_rejects_bad_schema(self):
        bad = [[], {}, {**record(), "timestamp": "2026-01-01T00:00:00"},
               {**record(), "timestamp": "2026-13-01T00:00:00Z"},
               {**record(), "timestamp": "2026-01-01T00:00:00+99:00"},
               {**record(), "timestamp": "2026-01-01T00:00:00+00:99"},
               {**record(), "source_ip": "not-an-ip"}, {**record(), "source_ip": 22},
               {**record(), "source_ip": "fe80::1%eth0"},
               {**record(), "user": "\x1b[31m"}, {**record(), "user": " "},
               {**record(), "user": "a" * 129}, {**record(), "outcome": "FAIL"},
               {**record(), "password": "not-accepted"}, {**record(), "service": None}]
        for row in bad:
            with self.subTest(row=row), self.assertRaises(ValueError):
                parse_event(json.dumps(row), 1)
        with self.assertRaises(ValueError):
            parse_event('{"user":"a","user":"b"}', 1)
        with self.assertRaises(ValueError):
            parse_event('{', 1)

    def test_default_service_and_trimmed_user(self):
        row = record(user=" demo ")
        row.pop("service")
        result = parse_event(json.dumps(row), 1)
        self.assertEqual((result.user, result.service), ("demo", "unknown"))

    def test_issues_keep_physical_lines_and_hide_content(self):
        rows = '\n' + json.dumps(record()) + '\nprivate-bad-content\n' + json.dumps(record(1))
        data, issues, count = read_events(io.StringIO(rows), Config())
        self.assertEqual([event.line for event in data], [2, 4])
        self.assertEqual(count, 4)
        self.assertEqual(issues[0]["line"], 3)
        self.assertNotIn("private", str(issues))

    def test_oversized_record_is_one_issue_then_recovers(self):
        source = 'x' * 150000 + '\n' + json.dumps(record()) + '\n'
        data, issues, lines = read_events(io.StringIO(source), Config())
        self.assertEqual((len(data), len(issues), lines), (1, 1, 2))
        self.assertEqual(data[0].line, 2)

    def test_line_limit_and_config(self):
        with self.assertRaises(ValueError):
            read_events(io.StringIO('\n\n'), Config(max_lines=1))
        for kwargs in ({"window_seconds": 0}, {"failure_threshold": 1}, {"spray_users": 1},
                       {"max_lines": -1}, {"max_lines": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                Config(**kwargs)


class DetectionTests(unittest.TestCase):
    config = Config(window_seconds=60, failure_threshold=3, spray_users=3)

    def report(self, rows):
        return analyze(events(rows), self.config)

    def test_inclusive_boundary_and_success_evidence(self):
        result = self.report([record(0), record(30), record(60), record(60, outcome="success")])
        self.assertEqual([f["rule"] for f in result["findings"]],
                         ["repeated_failures", "success_after_failures"])
        self.assertEqual([e["line"] for e in result["findings"][1]["evidence"]], [1, 2, 3, 4])

    def test_outside_window_does_not_match(self):
        result = self.report([record(0), record(30), record(61), record(62, outcome="success")])
        self.assertEqual(result["findings"], [])

    def test_sort_out_of_order_input(self):
        result = self.report([record(60, outcome="success"), record(20), record(10), record(0)])
        self.assertEqual(result["findings"][0]["evidence"][0]["line"], 4)
        self.assertEqual(result["findings"][-1]["rule"], "success_after_failures")

    def test_tied_times_follow_physical_line_order(self):
        rows = [record(0, outcome="success"), record(0), record(0), record(0)]
        self.assertEqual([f["rule"] for f in self.report(rows)["findings"]], ["repeated_failures"])

    def test_one_alert_per_active_burst_then_rearms(self):
        rows = [record(i) for i in range(7)] + [record(i) for i in (100, 101, 102)]
        findings = self.report(rows)["findings"]
        self.assertEqual(len(findings), 2)
        self.assertEqual([e["line"] for e in findings[1]["evidence"]], [8, 9, 10])

    def test_success_closes_pair_episode(self):
        rows = [record(i) for i in (0, 1, 2)] + [record(3, outcome="success"),
                record(4, outcome="success")] + [record(i) for i in (5, 6, 7)]
        self.assertEqual([f["rule"] for f in self.report(rows)["findings"]],
                         ["repeated_failures", "success_after_failures", "repeated_failures"])

    def test_distinct_users_not_failure_count(self):
        rows = [record(0), record(1), record(2, user="two"), record(3, user="three")]
        findings = self.report(rows)["findings"]
        self.assertEqual([f["rule"] for f in findings], ["multi_user_failures"])
        self.assertEqual(len(findings[0]["evidence"]), 4)

    def test_ip_service_and_user_isolation(self):
        rows = [record(0), record(1, service="vpn"), record(2, ip="192.0.2.11"),
                record(3, user="Demo"), record(4, outcome="success")]
        self.assertEqual(self.report(rows)["findings"], [])

    def test_success_does_not_clear_spray_history(self):
        rows = [record(0, user="a"), record(1, user="a", outcome="success"),
                record(2, user="b"), record(3, user="c")]
        self.assertEqual(self.report(rows)["findings"][0]["rule"], "multi_user_failures")

    def test_empty_is_valid(self):
        result = self.report([])
        self.assertEqual(result["summary"]["valid_events"], 0)
        self.assertIsNone(result["summary"]["first_event"])
        self.assertIn("does not establish", markdown(result))

    def test_markdown_escapes_untrusted_labels(self):
        result = self.report([record(i, user="<script>|[x]`*") for i in range(3)])
        text = markdown(result)
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;\\|\\[x\\]\\`\\*", text)

    def test_extreme_supported_date(self):
        row = record()
        row["timestamp"] = "0001-01-01T00:00:00Z"
        self.assertEqual(len(analyze(events([row]), self.config)["findings"]), 0)

    def test_repeat_runs_deterministic(self):
        rows = [record(i) for i in range(10)]
        self.assertEqual(self.report(rows), self.report(rows))

    def test_randomized_rules_against_simple_reference(self):
        # Independent O(n^2) reference scans all preceding rows rather than deques.
        rng = random.Random(818)
        for _ in range(30):
            rows = [record(rng.randrange(180), user=rng.choice(["a", "b", "c", "d"]),
                           outcome=rng.choice(["failure"] * 4 + ["success"]),
                           ip=rng.choice(["192.0.2.10", "192.0.2.11"])) for _ in range(60)]
            ordered = sorted(events(rows), key=lambda e: (e.timestamp, e.line))
            history, active_pair, active_source, resets, expected = [], {}, {}, {}, []
            for index, event in enumerate(ordered):
                pair = event.source_ip, event.user, event.service
                source = event.source_ip, event.service
                recent = [(i, e) for i, e in enumerate(history)
                          if (event.timestamp - e.timestamp).total_seconds() <= 60 and e.outcome == "failure"]
                pf = [e for i, e in recent if (e.source_ip, e.user, e.service) == pair and i > resets.get(pair, -1)]
                sf = [e for i, e in recent if (e.source_ip, e.service) == source]
                if len(pf) < 3:
                    active_pair[pair] = False
                if len({e.user for e in sf}) < 3:
                    active_source[source] = False
                if event.outcome == "success":
                    if len(pf) >= 3:
                        expected.append(("success_after_failures", [e.line for e in pf] + [event.line]))
                    resets[pair] = index
                    active_pair[pair] = False
                else:
                    pf.append(event)
                    sf.append(event)
                    if len(pf) >= 3 and not active_pair.get(pair, False):
                        expected.append(("repeated_failures", [e.line for e in pf]))
                        active_pair[pair] = True
                    if len({e.user for e in sf}) >= 3 and not active_source.get(source, False):
                        expected.append(("multi_user_failures", [e.line for e in sf]))
                        active_source[source] = True
                history.append(event)
            actual = [(f["rule"], [e["line"] for e in f["evidence"]]) for f in self.report(rows)["findings"]]
            self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
