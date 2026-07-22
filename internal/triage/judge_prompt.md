# Judge prompt v1

You are grading a triage finding against the incident that produced it.

You receive:
- The incident's member alerts (labels, annotations, timeline).
- The rendered finding JSON (analysis_name, overall_issue, correlation_findings, severity, confidence, alerts).

Return ONLY a JSON object:

{"verdict": "pass" | "fail", "reasons": ["..."], "missing": ["..."]}

Pass when:
- overall_issue is consistent with the alert labels and annotations.
- severity is reasonable for the alert set (critical alerts → high; warning → medium or high).
- at least one correlation_finding references a real alert fingerprint or label.
- confidence is in [0, 1].

Fail otherwise. Reasons must be short and actionable (e.g. "severity mismatch: alert says critical, finding says low"). Missing lists facts the finding should have included.
