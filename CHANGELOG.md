# Changelog

## [0.2.35] - 2026-10-14

### Security & Architecture
- **Architecture Contract & Security Guarantees Specification (#150)**: Added Section 20 to `docs/design/DESIGN.md` detailing the 4 interception surfaces, Zero-Leak invariant, fail-safe security posture, threat mitigation table, and Mermaid sequence data flow.
- **Fail-Safe Security Posture & Hardened Tool Detection (#209)**: Hardened `isCommandTool` inspection for both naming and argument shapes (`command`, `cmd`, `CommandLine`, `script`, `powershell`); added dedicated PowerShell `-EncodedCommand` / `-enc` base64 decoder with UTF-16LE and UTF-8 support; converted `tools/pre-execute` and tool guards to strictly fail-closed upon handler error in enforce mode; sanitized output blocks on `tools/post-execute` exceptions; gated updater minimum release age flag behind explicit option.

## [0.2.34] - 2026-10-14

### Added & Architecture
- **Fail-Fast Configuration Validation (#145)**: Added `resolveConfig` performing strict startup type, bounds, and enum checks on plugin configuration, rejecting malformed settings early with descriptive error details.
- **Pure Standard Library Isolation (#146)**: Decoupled all `lib/` modules from external runtime packages and Cordis interfaces to pure `node:*` primitives, enabling instant offline unit testing via `node --test`.
- **Architectural Separation of Sanitize & Mask (#147)**: Formally isolated irreversible redaction (`lib/sanitize.js`) for disk logging and billing from reversible prompt shielding (`lib/mask.js`) with zero cross-module side-effects.
- **Expanded Token Detection (#148)**: Extended secret scanner with high-precision detectors for GitHub fine-grained PATs (`github_pat_`), Slack API tokens (`xoxb-`/`xoxp-`), AWS STS keys (`ASIA`/`ABIA`), and HTTP Bearer authorization headers.
- **Browser Demasking Slot Preparedness (#149)**: Added `maskClientEnabled` configuration setting (default false) and client exchange architecture for future browser-side automatic demasking components.

## [0.2.33] - 2026-10-14

### Added & Reliability
- **Domain Persistence Schemas (#140)**: Implemented `AuditRecordSchema`, `SessionMappingSchema`, and `ConfigSchema` with `parse` / `safeParse` validation at storage boundaries, preventing corrupted configuration and database state.
- **Structured Domain Errors `AuditorError` (#141)**: Added `AuditorError` class hierarchy with machine-readable error codes (`ERR_BOUNDS_EXCEEDED`, `ERR_RESTORE_FAILED`, `ERR_STORAGE_UNAVAILABLE`, `ERR_VALIDATION_FAILED`) and sanitized diagnostic details.
- **Incremental Replacement Telemetry `stripInto` (#142)**: Added `stripInto` returning per-step replacement delta histograms (`{ [type]: count }`) and incrementing telemetry accumulators in real-time without persisting sensitive token values.
- **Safe Mapping Summaries `summarizeMapping` (#143)**: Added `summarizeMapping` generating sanitized edge-truncated sample previews (`sk****90`, `a****f`, `****`) for UI inspection without exposing cleartext credentials.
- **Counter Continuity on Restart `loadMapping` (#144)**: Added `loadMapping` parsing maximum numerical indices from existing placeholder tables (`<TYPE_N>`), guaranteeing continuous sequential numbering without collisions across host reboots.

## [0.2.32] - 2026-10-14

### Added & Performance
- **Ignorable Envelope Runtime Probe (#130)**: Added `probeIgnorableAppend(session)` safely testing whether host runtime or session envelope supports ignorable events, preventing session corruption on legacy host cores.
- **Deduplicated Event Gate (#131)**: Added `makeEventGate` managing adaptive audit event appending with per-session warning deduplication (`hasWarned`), emitting warning at most once per session and suppressing unsupported writes cleanly.
- **Stateless Mask Testing Tool (#137)**: Registered `shadow_auditor_mask_test` tool and exported `testMasking(text)` for ad-hoc stateless inspection of sensitive entity masking rules with entity frequency statistics.
- **Pluggable Detector Provider Seam (#138)**: Decoupled sensitive token discovery via pluggable `detector` option on `Stripper` and `StripperRegistry`, enabling runtime injection of domain-specific detector functions while defaulting to `findSensitiveMatches`.
- **LRU Session Eviction & Per-Session Store Limits (#139)**: Added LRU cache eviction in `StripperRegistry` (`maxSessions: 100`) and FIFO entry eviction in `Stripper` (`maxRestoreEntriesPerSession: 500`), guaranteeing bounded memory usage during long-running background operations.

## [0.2.31] - 2026-10-13

### Added & Performance
- **In-Memory Ring Buffer (#118)**: Added fixed-size in-memory ring buffer (`maxReportEntries: 200`) in `AuditRecorder` providing sub-millisecond RAM responses on `/events` and recent queries without disk I/O bottlenecks.
- **Chat Command `/shadow-auditor` (#119)**: Registered session command `/shadow-auditor` supporting `status`, `report`, and `restore <text>` subcommands with clean Markdown output and full English/Chinese localization.
- **Subagent Report Tool (#120)**: Registered `shadow_auditor_report` tool in DSH tools service allowing coordinating agents and subagents to inspect aggregated session security metrics and blocked actions.
- **Benchmark Attack Taxonomy Catalog (#122)**: Structured audit rules into canonical benchmark categories (`Family`: `instruction-injection`, `jailbreak`, `credential-leak`, `workspace-escape`) with standardized prefix IDs (`inj-001`, `jail-001`, `leak-001`, `esc-001`).
- **Standardized Severity Ranking (#123)**: Added numerical `severityRank(severity)` (0..3: low/info: 0, medium: 1, high: 2, critical: 3) with case-insensitive normalization, `rankToSeverity`, and `maxSeverity` threat resolution.

## [0.2.30] - 2026-10-13

### Added & Performance
- **Unicode NFKC Text Normalization (#113)**: Added `normalizeNfkc` in `diff-gate` to normalize visual mathematical letters, fullwidth glyphs, and homoglyphs to standard characters before pattern matching.
- **Head Scan Limit for Large Documents (#114)**: Added `maxScanChars` (default 10,000 for raw files) to bound scanning on megabyte-sized assets with `truncated: true` reporting.
- **Findings Limit per Scan (#115)**: Added `maxMatches` capping (default 100) preventing memory blowout and reporting `matchesCapped: true`.
- **Session Envelope Ignorable Flag (#116)**: Added `appendSessionEvent` and `recordToSession` stamping session-scoped audit records with `{ ignorable: true }` for safe backwards compatibility.
- **Typed Detection Event Registry (#117)**: Created `DetectionEvent` discriminated union registry (`dsh-shadow-auditor/detection`) with `createDetectionEvent` and `isDetectionEvent`.

## [0.2.29] - 2026-10-13

### Added & Performance
- **Runtime Agent Skill Registration (#99)**: Added `registerShadowAuditSkill` registering `shadow-audit-review` in DSH `skills` service upon availability with comprehensive security audit review instructions.
- **Diagnostic Error Sanitization (#100)**: Implemented `sanitizeError` and `sanitizeErrorMessage` masking host storage and drive paths (`<home>`, `<storage>`, `<drive>`, `<module>`) and suppressing internal stack traces in client diagnostics.
- **Aho-Corasick Multi-Pattern Automaton (#101)**: Integrated pure JS `AhoCorasick` automaton performing linear O(N + M) multi-keyword search across commands and diffs with BFS failure transitions.
- **Two-Phase Fast Scanner Architecture (#102)**: Added `TwoPhaseScanner` combining linear Aho-Corasick static needle search with targeted regex execution, eliminating regex evaluation on clean inputs.
- **Zero-Leak MatchInfo Invariant (#112)**: Implemented `createMatchInfo` and `toZeroLeakMatch` ensuring finding and event records store only safe masked snippets (`safeSnippet`), offsets, and types without raw plaintext secret strings.

## [0.2.28] - 2026-10-13

### Added & Performance
- **Plugin Sources & Patch Integrity Verification (#94)**: Implemented `checkPluginsPatchSources` inspecting `cordis.patch.yml` and plugin manifests, flagging unauthorized scopes (`@untrusted`), suspicious `eval` expressions, or untrusted git archive URLs.
- **Path Normalization in Reports & Feeds (#95)**: Added `norm(base, workspace, path)` replacing home directories with `<base>` and workspace roots with `<workspace>` across both POSIX and Windows path representations.
- **Protected Network Signatures (#96)**: Added `PROTECTED_SIGNALS` (`127.0.0.1`, `0.0.0.0`, `::1`, `::`, `localhost`) preserving critical loopback diagnostic signals from sanitizer redaction.
- **Weighted Session Security Score (#97)**: Implemented `calculateSecurityScore` calculating an aggregated security index (0..100) and status ratings (`Safe`, `Needs Attention`, `Dangerous`) based on `SEVERITY_WEIGHT`.
- **Diff Gate LRU Caching (#98)**: Added LRU result cache (512 entries) keyed by `sha256(content) + rulesetVersion`, invalidating automatically on `setRulesetVersion`.

## [0.2.27] - 2026-10-13

### Added & Host Auditing
- **Audit Directory & Socket Permissions Check (#89)**: Added `checkConfigPermissions` auditing POSIX file modes (`stat.mode`) for audit logs, secret stores, and sockets against `0700` and `0600` ceilings with safe Windows no-op.
- **Process Environment Variable Secrets Audit (#90)**: Implemented `checkEnvSecrets` inspecting `process.env` keys and values, identifying unmasked provider keys while safely masking credentials.
- **Supply Chain Live CVE Check via npm Audit API (#91)**: Added `checkDepsSupplyChain` querying official npm audit endpoint with an AbortController timeout (3000ms) and offline degradation.
- **Network Interface & Wildcard Listener Inspection (#92)**: Implemented `checkNetworkBindings` analyzing Linux procfs `/proc/net/tcp` and `os.networkInterfaces` to flag external wildcard listeners on 0.0.0.0 or :: without loopback boundaries.
- **Historical Session Archive Stream Scanner (#93)**: Added `checkSessionsSensitive` streaming through `.jsonl`, `.gz`, and `.zst` archives with memory bounds and secret pattern matching.

## [0.2.26] - 2026-10-13

### Added & Security Hardening
- **Cooperative Timeout Budget (#84)**: Implemented configurable execution budgets (`timeoutMs`, `onTimeout: "allow" | "block"`) with cooperative checkpoints in lifecycle guards (`withTimeoutBudget`, `isBudgetExceeded`).
- **Local Ollama Command Classification (#85)**: Added asynchronous local LLM command risk classifier (`classifyCommand`) with borderline score heuristics (0.4-0.6) and deterministic rule-based fail-safe fallback.
- **Audit Report Integrity Checksum (#86)**: Integrated SHA-256 cryptographic checksum (`calculateReportChecksum`, `verifyReportChecksum`) into audit bills and reports ensuring tamper detection.
- **Host Security Audit Tool (#87)**: Registered `shadow_auditor_system_audit` tool and `runSystemAudit` engine covering config, env, sensitive paths, plugins, and network boundaries.
- **Configuration Secrets Scanner (#88)**: Implemented `checkConfigSecrets` recursively inspecting YAML/JSON/env configuration files while skipping placeholders and safely masking detected keys.

## [0.2.25] - 2026-10-13

### Added & Security Validation
- **Multilingual Prompt Injection Defense (#76)**: Added detection for instruction overrides, role switching, system prompt leaks, and tool abuse across English and Chinese prompt environments.
- **Shannon Entropy Secret Detection (#77)**: Implemented `calculateShannonEntropy` / `shannonEntropy` (threshold >= 4.5 bits/char, len >= 24, classes >= 2) in Diff Gate and secrets scanning, filtering UUIDs and SHA digests while identifying unstructured high-entropy tokens.
- **Luhn Algorithm Card Verification (#78)**: Integrated `luhnValid` into `lib/redact.js` to accurately mask 13-19 digit payment cards while eliminating false positives on timestamps and order numbers.
- **Calendar Date Validation for CN-ID (#79)**: Added `isValidCalendarDate` checking embedded dates (YYYYMMDD) including leap years and calendar day limits before redacting document numbers.
- **IPv4 Octet Range Validation & Semver Protection (#80)**: Added `isValidIpv4` (0-255 range per octet) and `redactIpv4` with loopback preservation, preventing redaction collisions with semver package strings (e.g. `1.2.3.400`).

## [0.2.24] - 2026-10-13

### Fixed & Performance
- **Audit Recorder Tail Reading & Telemetry (#67, #69, #70, #71, #72)**: Optimized audit recorder log tail reading and real-time telemetry streaming.

## [0.2.23] - 2026-10-09

### Fixed
- **Cordis Proxy Isolation Safety (#133)**: Wrapped `ctx.storageDomain` detection in top-level `try/catch` block to safely catch Cordis proxy access exceptions when `storageDomain` is not injected, ensuring deterministic fallback to in-memory session mode without unhandled errors.

## [0.2.22] - 2026-10-09

### Added & Architecture
- **Reversible Masking & Placeholder Engine (#126)**: Implemented session-scoped reversible PII and secret stripping via `Stripper` using monotonic `<TYPE_N>` placeholders with localized restoration tables.

## [0.2.21] - 2026-10-08

### Added & Security
- **Static Environment Variable Path Expansion (#107)**: Expanded Windows and Unix environment variable tokens (`$HOME`, `~/`, `%USERPROFILE%`, `%TEMP%`, `$env:*`) during protected prefix checks.
- **Embedded URL Credentials Interception & Masking (#81)**: Intercepted and redacted basic auth credentials embedded in command URLs (`https://user:pass@host`).
- **Single-Pass Stage Partitioning & Regex Caching (#68)**: Optimized command guard multi-stage inspection with single-pass scanning and LRU regex caching.

## [0.2.19] - 2026-10-08

### Security & Hardening
- **Unwrap Before structuredClone (#169, #180, #183)**: Inverted configuration unwrap order (`plainConfig(Config(structuredClone(plainConfig(src))))`) to prevent `DataCloneError` on Schemastery Volatile boxes, eliminating fail-open guard bypasses.
- **Zero-Leakage Invariant in Scanner & Evidence (#171, #172)**: Removed raw unmasked secrets from `scanSecrets` output hits. Masked passwords (`[REDACTED]`) and exfiltration tokens in SAST and prompt-injection finding `evidence`.
- **ReDoS Protection & Regex Caching (#175)**: Implemented `getSafeRegExp` with LRU caching, pattern length limits, and rejection of catastrophic backtracking nested quantifiers in user-supplied command and path rules.
- **Route Error Masking & Limit Clamping (#177, #178)**: Guarded against `NaN` parameters on `/events` and `/export`, returning sanitized generic JSON errors without leaking internal stack traces.

### Fixed
- **Audit Log Retention & Rotation Calculations (#168, #170)**: Converted `maxFileSizeMb` and `retentionDays` to positive numbers, fixing perpetual failure of log rotation caused by `NaN` calculations on Volatile boxes. Added dynamic `recorder.updateConfig` on `loader/volatile-update`.
- **Tool-Name Matching False Positives (#173)**: Replaced broad substring matching with strict regex matchers (`isCommandTool`, `isFileReadTool`, `isFileWriteTool`), eliminating false positives on benign tools like `profile`, `list_fs`, `rewrite`.
- **Turn Filter & Limit Slicing (#176, #69)**: Corrected `--turn` filter to evaluate in-flight and completed turns prior to applying `limit` slicing.
- **Memory-Bounded Log Consumption (#174)**: Bounded memory consumption in `AuditRecorder.readAll()` with `maxRecords` cap and stream-level session filtering.
- **Dead Code Cleanup (#179, #72)**: Removed duplicated `debugFailure` method definition in `AuditRecorder`.
- **Façade Decoupling & Route Extraction (#182)**: Extracted HTTP routes into `lib/routes.js`, reducing `lib/index.js` to 468 lines (< 500 lines).

## 0.2.18

### Fixed
- **Peer gate on DSH 0.2.0-rc.1** (#58): the bundle was skipped at profile startup because its `peerDependencies` excluded the running version.
- **Settings card served no form**: `NS` was the package name rather than the profile entry id, `Config` declared no `.volatile()` field, and `getConfig` handed out `Volatile` boxes. Both 0.1.7-rc.2 and 0.2.0 now serve and read the form.
- **A saved setting never took effect**: the host applied changes through `settings.register` and `scope.watch`, neither of which exists in either release. Changes are applied on `loader/volatile-update` now.
- **`settings.plugin.item` registration removed**: retired before DSH 0.1.7-rc.2, so it only registered the card a second time on a seat that no longer exists.

## 0.2.17

### Fixed
- **Peer gate on DSH 0.2.0-rc.1** (#58): DSH skips a profile bundle whose `peerDependencies` exclude the running version, so this plugin was absent from the profile with no error in the UI. Every `@deepseek-ai/dsh-*` peer now names both the 0.1.7-rc.2 and 0.2.0-rc.1 lines, because semver does not admit a prerelease of the next minor into a range that does not name it.

All notable changes to `@goodandready/dsh-shadow-auditor` are documented in this file.

## [0.2.16] - 2026-09-26

### Security
- **Hardened Endpoint Verification (`isTrustedRequest`) (#73)**: Strictly reject cross-site and same-site requests (`Sec-Fetch-Site: cross-site`, `same-site`) even when originating from loopback. Enforce exact matching for session Bearer and cookie tokens against expected secrets, while allowing safe same-origin WebUI card requests.
- **Sanitized Distribution Mirroring (#50)**: Enhanced GitHub publishing script to strictly isolate internal documentation, plans, and design records from public mirror releases, ensuring only public product files and verified documents are distributed.

### Added
- **Keyboard-Accessible Settings Card Header (#156)**: Replaced non-semantic header element with a fully accessible interactive button (`role="button"`, `type="button"`, `tabIndex="0"`), ARIA state exposure (`aria-expanded`, `aria-controls`), Enter and Space key activation, `:focus-visible` focus ring, and reduced-motion styling.
- **Deterministic Host-Contract Test Harness (#157)**: Introduced hermetic in-memory Cordis runtime harness (`test/harness.mjs`) and integration tests (`test/host-contract.test.mjs`) validating plugin lifecycle, tools, guards, web routes, commands, and telemetry boundaries deterministically without network prerequisites or skipped tests.

### Fixed
- **Client Slot Effect-Binding & Disposer Teardown (#121)**: Wrapped all UI slot injections and locale registrations inside Cordis `ctx.effect`, returning clean unbind disposers to prevent event listener and timer leaks across plugin hot-reloads.

## [0.2.15] - 2026-09-24

### Added
- **Destructive Deletion Workspace Guard (#103)**: Strictly block recursive deletions (`rm -rf`, PowerShell `Remove-Item -Recurse`, `rd /s`, `git clean -fdx`) targeting filesystem root (`/`, `~`, `.`) or paths resolving outside the session workspace.
- **Critical System Prefix Protection (#105)**: Unconditional protection for sensitive system directories (`~/.dsh`, `~/.claude`, `~/.ssh`, `/etc`, `/usr`, `C:\Windows`), preventing deletion even when the session workspace is located in the home directory.
- **Dry-Run Pass-Through Verification (#104)**: Recognize verification and preview flags (`-WhatIf`, `-Confirm`, `--dry-run`, `git clean -n`), позволяя safe preview commands without triggering false-positive deletion blocks, while recording safety audits.

### Fixed
- **Diff Gate Unified Detection Heuristic (#65)**: Fixed false-positive `isUnifiedDiff` heuristic that misclassified regular files containing `@@` markers as diffs and bypassed security scans in `scanFileContent`.

### Performance
- **Diff Gate Large File Scan Optimization (#66)**: Hoisted diff heuristic outside the per-line loop in `scanDiff`, eliminating $O(N \cdot M)$ string operations and reducing 5000+ line diff scan latency from quadratic freeze to ~20ms.

## 0.2.14

### Fixed
- The settings card no longer waits for the removed `settingsScope` service. It uses `configForms` on current DeepSeek Harness (#74).

## [0.2.13] - 2026-09-19

### Fixed
- **Settings reachable again on the plugin's own page**: the current DSH core
  (0.1.6-alpha.2) renders a plugin's configuration page only for entries registered
  in the plugin-list seat `plugins.item`. The view-aware card is now registered there
  (`id: 'dsh-shadow-auditor'`, order 60, static label); the row seat and the legacy
  `settings.plugin.item` card stay as fallbacks.

## [0.2.12] - 2026-09-19

### Fixed
- **Settings reachable again**: the card registered into `settings.plugin.item`, a
  slot the current DSH core (0.1.6-alpha.2) no longer renders, so the plugin's
  settings were unreachable. The surface now registers into the Plugins page row
  seat `plugins.row.config`, keyed
  `@goodandready/dsh-shadow-auditor#dsh-shadow-auditor`
  (`rowConfigKey(package, rowId)`): the plugin's row gains a configure control whose
  page is the settings form (`view: 'page'`, without our card chrome and header —
  the host page draws the title, icon, crumb and padding) plus a one-line state for
  `view: 'summary'`. The legacy seat stays registered as a fallback for older cores.

### Added
- Guard `test/row-seat.test.mjs`: the row key is checked against `package.json` and
  the row id in `cordis.patch.yml`, the seat order must put the row seat first, and
  the page view must drop the card chrome.
