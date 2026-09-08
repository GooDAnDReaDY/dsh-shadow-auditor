# Findings: Code-Security Diff Gate (#39)

- Scanner must operate on line-based unified diffs or whole file content changes.
- Bounded performance: Limit scan length (e.g. max 500 KB per diff chunk) to prevent event-loop freezing.
- Redaction: Any evidence string emitted in findings must be processed through redaction engine so secrets are never echoed in findings or logs.
