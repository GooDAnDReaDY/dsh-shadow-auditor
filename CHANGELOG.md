# Changelog

## [0.2.22] - 2026-10-09

### Added & Architecture
- **Reversible Masking & Placeholder Engine (#126)**: Implemented session-scoped reversible PII and secret stripping via `Stripper` using monotonic `<TYPE_N>` placeholders with localized restoration tables.
- **Monotonic Counters & Value Reuse (#127)**: Guaranteed consistent placeholder reuse for repeated secret and PII entities across multiple turns in a session.
- **Descending Length Demasking (#128)**: Demasked placeholders strictly in descending order of length to eliminate prefix collisions (e.g. `<KEY_12>` before `<KEY_1>`).
- **Interval-Based Overlap Resolution (#129)**: Implemented greedy non-overlapping interval selection sorting by start ascending, score descending, and span length descending.
- **Persistent Storage Integration & Fallback (#132, #133)**: Persisted session restoration tables using DSH `storageDomain` (`'dsh_shadow_auditor'`) with graceful in-memory fallback and single informational diagnostic log.
- **Async Storage Lifecycle Safety (#134)**: Prevented race conditions and unhandled rejections during plugin unloading while `storageDomain` is resolving.
- **Session Log Cleanliness Invariant (#135)**: Pre-filtered user prompts on `agent/pre-step` and sanitized audit log arguments, ensuring zero raw secrets are stored in session logs or forwarded to LLM prompts.
- **Session Demasking Command (#136)**: Registered session command `/shadow-auditor restore <text>` for authorized local demasking on client terminals.
- **Web UI Settings Sync**: Added `enableReversibleMasking` configuration toggle in Section 1 with 100% English and Chinese localization dictionary parity.

## [0.2.21] - 2026-10-09

### Added & Architecture
- **Guaranteed Priority Hook Execution (#125)**: Registered all security lifecycle hooks with Cordis `{ prepend: true }` so audit policies execute ahead of any user or third-party hooks.
- **Unconditional Critical Threat Blocking (#124)**: Added `secretBlockCritical` schema configuration to unconditionally block destructive system commands and master secret leaks, bypassing soft audit modes (`shellGuardMode: 'audit_only'`, `diffGateMode: 'warning'`).
- **DSH User Approval Integration & Ask Mode (#108)**: Supported `shellGuardMode: 'ask'` returning `{ kind: 'ask', reason, displayReason }` in `tools/pre-execute` for interactive confirmation via DSH user approval dialogs.
- **Multi-Surface Lifecycle Interception Architecture (#109)**: Unified boundary security across `agent/pre-step`, `tools/guard`, `tools/pre-execute`, `tools/post-execute`, and `tools/result`.
- **Prompt Injection Pre-Filtering (#110)**: Scanned user prompts on `agent/pre-step` before LLM processing, rejecting jailbreak and system-override attempts early (`{ kind: 'reject' }`).
- **Tool Result Output Sanitization & Redaction (#111)**: Intercepted tool outputs on `tools/post-execute` and masked exposed credentials and high-entropy secrets using `maskSecret()` before context injection.

## [0.2.20] - 2026-10-09

### Security & Hardening
- **Homoglyph & Zero-Width Normalization (#82)**: Neutralized invisible Unicode zero-width characters and Cyrillic/Greek homoglyphs before evaluation in CommandGuard.
- **Hidden Base64 Payload Inspection (#83)**: Recursive decoding and deep scanning of hidden Base64 payloads (UTF-8 and UTF-16LE encoded commands).
- **PowerShell & cmd.exe Destructive Pattern Hardening (#106)**: Added detection patterns for Windows-specific destructive commands (`Remove-Item`, `Format-Volume`, `Stop-Computer`, `rd /s /q`, `del /f /q`, `vssadmin delete shadows`).
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
- **Dry-Run Pass-Through Verification (#104)**: Recognize verification and preview flags (`-WhatIf`, `-Confirm`, `--dry-run`, `git clean -n`), allowing safe preview commands without triggering false-positive deletion blocks, while recording safety audits.

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
