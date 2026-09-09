# Findings: Stability Refinements (#41)

- `secret-write` regex must target actual secret storage patterns (`.env`, `.credentials`, `.git-credentials`, `.netrc`, `.pgpass`, `id_rsa`, `key.pem`) instead of any file with substring 'token' or 'secret'.
- SAST lines that are purely comments (//, #, /*, *) must be skipped.
- `fs.readFileSync(new URL('...', import.meta.url))` must not trigger path traversal.
- Test and doc files should skip prompt injection detection.
- `/audit` must default to `readRecent(flags.limit || 50)`.
