"""Plain Markdown rendering with escaped table cells and HTML characters."""
import html


def cell(value):
    text = html.escape(str(value), quote=True)
    for char in ("\\", "`", "*", "_", "[", "]", "|", "~"):
        text = text.replace(char, "\\" + char)
    return text.replace("\n", " ").replace("\r", " ")


def markdown(report):
    summary, config = report["summary"], report["config"]
    out = ["# Authentication triage report", "",
           "Offline rule matches for analyst review. A match is not proof of an attack or account compromise.", "",
           f"Valid events: {summary['valid_events']} | Invalid records: {summary['invalid_records']} | Findings: {summary['findings']}",
           f"Window: {config['window_seconds']}s, inclusive. Failure threshold: {config['failure_threshold']}. Distinct-user threshold: {config['spray_users']}.",
           "", "## Findings", ""]
    if not report["findings"]:
        out += ["No rule matched. This does not establish that the activity is safe.", ""]
    for finding in report["findings"]:
        out += [f"### {finding['id']}: {finding['rule']} ({finding['severity']})", "",
                cell(finding["reason"]), "", "| Line | Timestamp (UTC) | Source | User | Service | Outcome |",
                "| --- | --- | --- | --- | --- | --- |"]
        for event in finding["evidence"]:
            out.append("| " + " | ".join(cell(event[key]) for key in
                       ("line", "timestamp", "source_ip", "user", "service", "outcome")) + " |")
        out.append("")
    out += ["## Input issues", ""]
    if report["issues"]:
        out += [f"- Line {issue['line']}: {cell(issue['reason'])}" for issue in report["issues"]]
    else:
        out.append("None.")
    out += ["", "## Review before acting", "",
            "- Check the source export and the referenced physical line numbers.",
            "- Ask whether a shared IP, a service account or a client retry explains the activity.",
            "- Correlate device, MFA and session evidence before concluding compromise.",
            "- Treat reports as sensitive: they contain usernames and source addresses.", ""]
    return "\n".join(out)
