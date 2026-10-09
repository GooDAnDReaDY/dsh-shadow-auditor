# DESIGN.md — @goodandready/dsh-shadow-auditor

## Product / Purpose
- Назначение: Фоновый аудит безопасности, детект утечек секретов в коде/дифах, защита от разрушительных шелл-команд, эксфильтрации данных и шлюз безопасности кода (Code-Security Diff Gate) в DeepSeek Harness (DSH).
- Аудитория: Разработчики и администраторы инсталляций DeepSeek Harness.
- Статус: Активный production-плагин (v0.2.x).

## User Surfaces
- Web/UI: Карточка настроек плагина во вкладке «Настройки → Плагины → Настройки плагинов» (`settings.plugin.item`).
- DSH UI / settings / slots: Слот `settings.plugin.item` со сворачиваемой карточкой `PluginCard`; слот `conversation.session.header.utilities` для значка безопасности `AuditShieldChip`.
- API: HTTP GET `/dsh-shadow-auditor/audit` (JSON со статусом последнего сканирования и конфигурацией).
- CLI: Слэш-команда `/audit` в чате DSH с флагами `--turn`, `--all`, `--json`, `--since=YYYY-MM-DD`, `--limit=N` (по умолчанию 50 последних записей).
- Документация: `README.md`, `README.ru.md`, `README.zh.md`.

## Visual Direction
- Атмосфера: Строгий, нативный стиль ядра DSH без визуального шума.
- Утверждённые референсы: Карточки настроек ядра DSH («Консоль», «Цикл агента»).
- Не копировать: Сторонние UI-библиотеки, несоответствующие ядру стили, инлайновые хардкод-цвета.

## Foundations
- Цвета и роли: Исключительно CSS-переменные темы DSH (`--dsw-alias-border-l2`, `--dsw-alias-bg-layer-3`, `--dsw-alias-label-primary`, `--dsw-alias-label-secondary`, `--dsw-alias-color-danger`, `--dsw-alias-color-warning`, `--dsw-alias-color-success`).
- Типографика: Системный шрифт ядра DSH; заголовки 15px/600, пояснения 13px, бейджи 12px.
- Сетка, отступы, responsive: Радиус карточки 12px, паддинги 14px 16px, поля форм с отступами 12px.
- Accessibility: Заголовок карточки является нативной кнопкой с `aria-expanded`, поля формы снабжены `label` и `disabled`-состояниями при недоступности бэкенда.

## Components And States
- Компоненты: `PluginCard` со сворачиваемой шапкой, статусным бейджем (GREEN/YELLOW/RED), шевроном раскрытия, переключателями защит и полями конфигурации логирования;
  - `AuditShieldChip`: интерактивный чип-щит в шапке сессии (`conversation.session.header.utilities`), отображающий уровень безопасности в реальном времени с всплывающим окном.
- Loading / empty / error / success:
  - `loading`: Отображение индикатора загрузки `Загрузка…` / `Loading…`.
  - `unavailable`: Блокировка формы (`disabled`), индикатор `Настройки временно недоступны` / `Settings service unavailable`.
  - `error`: Вывод сообщения об ошибке сохранения в подвале карточки.
  - `success`: Вывод уведомления `Сохранено` / `Saved`.
- Формы, валидация и действия:
  - Чекбоксы: `strictSecretScanning`, `blockDangerousCommands`, `enableAuditBadge`, `enableAuditLog`.
  - Числовые поля: `maxFileSizeMb` (лимит файла в МБ), `retentionDays` (хранение в днях).
  - Кнопка «Сохранить» / «Save» с анимацией сохранения.

## User Flows
- Настройка политик аудита: открытие «Настройки → Плагины», раскрытие карточки «Теневой аудитор безопасности», изменение параметров, сохранение.
- Оперативный аудит в чате: ввод `/audit` в диалоге, получение сводной Markdown-ведомости операций и заблокированных действий агента.

## Do / Don't
- Do: Проверять `status` снимка настроек (`ready` vs `unavailable` vs `loading`), блокировать контролы при `unavailable`.
- Do: Использовать `ctx.slots.inject('settings.plugin.item', ...)` без delayed fallback таймеров.
- Don't: Использовать захардкоженные цвета (`#fff`, `#000`), хардкодить `setTimeout` fallback на `settings.section`.

## Locked Design Decisions
- 2026-09-02 — Карточка настроек размещается строго в `settings.plugin.item`; отдельный боковой раздел запрещён, чтобы не загромождать плоский список навигации ядра.
- 2026-09-06 — При `snap.status !== 'ready'` форма и кнопка сохранения блокируются (`disabled: true`), предотвращая ложное редактирование при недоступности сервиса настроек.
- 2026-09-08 — Интерактивный бейдж безопасности `AuditShieldChip` зарегистрирован в слот `conversation.session.header.utilities` (`id: 'dsh-shadow-auditor-chip'`) с полной изоляцией стилей и переменными тем ядра DSH.
- 2026-09-08 — Чтение журнала аудита ограничено `readRecent(limit)` без распаковки архивных `.gz` файлов для исключения OOM.
- 2026-09-08 — Исключены ложные срабатывания безопасных команд (разрешены `grep -i kill`, `systemctl status`, `systemctl is-active`).
- 2026-09-08 — Утечки памяти устранены: карты сессий снабжены LRU-ограничением и слушателями очистки при уничтожении сессий.
- 2026-09-08 — Удален шумный инструмент `shadow_auditor_rules_list`; политики безопасности функционируют декларативно.
- 2026-09-08 — Интегрирован Code-Security Diff Gate (v0.2.6): инспекция диффов и модификаций файлов по трём доменам (Secrets с энтропией Шеннона, SAST-паттерны SQLi/Command Injection/Path Traversal/Eval, эвристики Prompt-Injection).
- 2026-09-08 — Поддерживаются режимы diffGateMode: disabled, warning (формирование находок и аудит), block (блокировка выполнения с рекомендациями по исправлению).
- 2026-09-08 — Реализован механизм подавления ложных срабатываний через директиву в коде `// shadow-audit-ignore: <ruleId>` или `# shadow-audit-ignore: <ruleId>`.
- 2026-09-08 — Рекомендации по исправлению строго рекомендательные (suggestion-only); автоматическое изменение или коммит кода шлюзом запрещены.
## 10. v0.2.7 Stability Refinements & False-Positive Elimination

### 10.1 False-Positive Elimination in Command Guard
- Refined `secret-write` regex in `lib/guards/command.js`: destination targeting now strictly matches credentials and secret files (`.env`, `.credentials`, `.git-credentials`, `.netrc`, `.pgpass`, `id_rsa`, `id_ed25519`, `*key.pem`) without falsely matching developer scripts such as `check_token.js` or test suites `test_secret.py`.

### 10.2 Noise Suppression in Diff Gate SAST
- Lines recognized as comments (`//`, `#`, `*`, `/*`) bypass dynamic code execution and SQL injection rules in `lib/diff-gate/sast.js`, eliminating false alerts on explanatory comments while keeping real secret detection intact.
- Path traversal (`SAST-PATH-001`) permits safe resolution via `import.meta.url` and `__dirname`.

### 10.3 Test Suite & Documentation Isolation in Diff Gate
- Prompt injection heuristics are bypassed for test files (`test/**`, `*.test.*`, `*.spec.*`) and fixtures, enabling security test suites to run without self-blocking.
- Overly long lines in unified diffs (> 2048 characters) are truncated before scanning to eliminate CPU lockup on minified bundles.

### 10.4 Slash Command Memory Safety & UI Polling
- `/audit` slash command in chat defaults to bounded reading (`readRecent(flags.limit ?? 50)`) unless explicitly invoked with `--all`, preventing memory bloat on large audit journals.
- `AuditShieldChip` in `lib/client.js` suspends HTTP polling while the browser tab is hidden (`document.hidden`), preserving server and client CPU resources.
- Audit archive rotation errors are safely logged through plugin logger.

## 11. v0.2.8 UI Design System Unification & Robustness

### 11.1 Visual Styling Aligned with `dsh-clinebot`
- **Container Structure**: Adopted four clean, structured section cards (`.sa-section-card`, `.sa-grid-2`, `.sa-row`) matching the DSH design system layout:
  1. `Execution Safety & Guards` (Strict secrets, dangerous command interception, shield chip toggle).
  2. `Code-Security Diff Gate & SAST` (Policy select: Disabled/Warning/Block, SAST analysis toggle, Prompt-injection scanner toggle).
  3. `Audit Trail & Storage` (Persistent JSONL log toggle, gzip size threshold, retention days).
  4. `Live Telemetry & Diagnostics` (Real-time security shield status, recent interception hits with labels and timestamps).
- **Design Tokens**: Standardized onto native DSH variables (`--dsw-alias-border-l2`, `--dsw-alias-bg-layer-3`, `--dsw-alias-bg-layer-2`, `--dsw-alias-label-primary`, `--dsw-alias-label-secondary`, `--dsw-alias-state-brand-primary`).
- **Isolation**: Clean `<style>` tag injection with `id="dsh-shadow-auditor-full-css"` and `data-dsh-plugin="@goodandready/dsh-shadow-auditor"`.

### 11.2 Settings Synchronization & Catch Hardening
- Client draft state correctly binds and syncs `diffGateMode`, `enableSastScan`, and `enablePromptInjectionScan` from the settings snapshot.
- Replaced silent empty catch blocks in `lib/index.js` and `lib/client.js` with logger warnings.

## 12. v0.2.9 Canonical Localization, Packaging Hygiene & Security Evolution

### 12.1 Canonical Language Standard & Localization Policy
- **English & Chinese Only**: Runtime code, guard error messages, slash commands, default notifications, and UI locale dictionaries in `lib/client.js` are strictly in canonical English (`en`) and Chinese (`zh`).
- **Russian Translation Governance**: In accordance with `dhs-plugin-release-workflow`, all Russian UI translations are extracted from plugin code and submitted as tracking issues to `goodandready/dsh-russian-lang` on Gitea.
- **Multilingual Documentation**: `README.md`, `README.ru.md`, and `README.zh.md` remain synchronized in the repository.

### 12.2 Clean Distribution Packaging
- Non-product files (`AGENTS.md`, `index.md`, internal plans, scratch scripts) are untracked from git and excluded from release tarballs.
- Package files are strictly validated with `npm pack --dry-run --json` against the 256 KiB per-file limit.

### 12.3 Five Core Functional Capabilities
1. **Real-Time Interception Feed & Session Log Viewer**:
   - HTTP endpoint `GET /dsh-shadow-auditor/events` with query parameters (`limit`, `filter`, `sessionId`).
   - Interactive UI filter tabs (`All`, `Shell Guard`, `Diff Gate`, `High Risk`) with live refresh.
2. **Configurable Security Policies & Custom Blacklists**:
   - `customBlockedCommands`: multiline regex patterns to block arbitrary shell commands.
   - `sensitivePathPatterns`: multiline file patterns to guard sensitive files.
   - `shellGuardMode`: toggle between `enforce` (blocking) and `audit_only` (warning-only).
3. **Diff Gate Visual Inspector & Safe Remediation Preview**:
   - Structured remediation guidance (`💡 Safe Remediation Suggestion`) rendered directly inside Diff Gate findings.
4. **File Integrity & Secret Anchor Monitor**:
   - Interception of file tools (`read_file`, `write_to_file`, etc.) accessing sensitive credentials or anchors (`.env`, `settings.yaml`, `id_rsa`, `server.key`).
5. **Security Audit & Compliance Export**:
   - HTTP endpoint `GET /dsh-shadow-auditor/export` producing JSON telemetry records or formatted Markdown Operation Bills.
   - UI export buttons in header.


## 13. Command Guard False-Positive Scope (#56)

- rm -f without a recursive flag is allowed. Any rm option group containing r, including -r, -rf, -fr, and split flags, remains blocked.
- Secret and environment write checks run independently on commands separated by semicolon, &&, ||, pipe, and newlines. Quoted or escaped separators do not split the text.
- Reading settings.yaml with grep, cat, or sed without -i is allowed. Redirection, tee, and in-place edits targeting protected files remain blocked.
- This change does not alter network exfiltration, destructive SQL, service control, protected Git operations, device writes, or workspace escape rules.

## 14. Native DSH Design Tokens & Route Security (#49, #52, #55)

- **Strict Theme Variable Conformance**:
  - All hex colors and raw `rgba(...)` instances in `lib/client.js` are replaced with native DSH CSS custom properties:
    - Success states: `var(--dsw-alias-state-success-primary)` and `color-mix(in srgb, var(--dsw-alias-state-success-primary) 8%, transparent)`.
    - Warning states: `var(--dsw-alias-state-warning-primary)` and `color-mix(in srgb, var(--dsw-alias-state-warning-primary) 8%, transparent)`.
    - Error / Danger states: `var(--dsw-alias-state-error-primary)` and `color-mix(in srgb, var(--dsw-alias-state-error-primary) 8%, transparent)`.
    - Brand / Action states: `var(--dsw-alias-state-brand-primary)`.
    - Elevations & Borders: `var(--dsw-alias-shadow-l2)`, `var(--dsw-alias-border-l2)`, `var(--dsw-alias-bg-layer-2)`, `var(--dsw-alias-bg-layer-3)`.
- **HTTP Endpoint Security & Method Restrictions**:
  - All audit endpoints (`/dsh-shadow-auditor/audit`, `/events`, `/export`) strictly enforce HTTP `GET`/`HEAD` methods, responding with `405 Method Not Allowed` on other verbs.
  - Fail-closed caller verification via `isTrustedRequest` validates Loopback IP, `sec-fetch-site: same-origin`, Bearer auth, or valid session cookie. Untrusted callers receive `403 Forbidden`.
  - Exported configuration data is sanitized via `sanitizeExportConfig` to prevent exposure of internal or sensitive patterns.
- **Client Locale Lifecycle**:
  - UI locale dictionaries (`en` and `zh`) are registered inside `ctx.effect` with an explicit undo disposer for clean re-mount and hot-reload behavior.


## 15. Export Hygiene and Audit Record Visibility (#54, #60)

- **Diff Gate vs. Full File Inspection (`scanFileContent`)**:
  - `scanFileContent` in `lib/diff-gate/gate.js` is wired directly into production write guards (`lib/index.js`). Non-diff plain text file write payloads are evaluated through `scanFileContent` while patch diffs run through `scanDiff`, guaranteeing secret scanning, SAST, and prompt injection detection on all write surfaces.
- **Dead Export Purge (`isTrustedReadRequest`)**:
  - Unused dead export `isTrustedReadRequest` in `lib/updater.js` removed; read endpoints use the canonical `isTrustedRequest` helper.
- **Audit Persistence Visibility & Error Handling**:
  - `AuditRecorder` tracks `recordErrors` and `unreadableCount`, surfaced via `recorder.getStats()`.
  - Failed `record()` executions are explicitly caught and logged to `logger.warn`, preventing silent audit loss.
  - All intentional empty suppressions in cleanup/unregistration paths carry explicit `/* intentional: best-effort ... */` code annotations.

## 16. Audit Stabilization & Hardening Architecture (#168-#183)

### 16.1 Config Unwrapping & Volatile Box Preservation (#169, #180, #183)
- **Unwrap Order**: To prevent `DataCloneError: () => current could not be cloned` from Schemastery Volatile boxes, configuration is unwrapped via `plainConfig` prior to `structuredClone`, following `Config(structuredClone(plainConfig(src)))`.
- **Single Assignment**: Removed dead initial `getConfig` assignment in `lib/index.js`, maintaining a resilient fallback `readConfig` function that survives box deserialization.

### 16.2 Bounded Retention & Dynamic Size Configuration (#168, #170)
- **Safe Numeric Parsing**: `AuditRecorder` strictly converts `maxFileSizeMb` and `retentionDays` using `Number()` with safe positive fallbacks (50 MB, 30 days), preventing `NaN` evaluation on `??` operator against Volatile boxes.
- **Dynamic Reconfiguration**: Added `recorder.updateConfig({ maxFileSizeMb, retentionDays })` executed on `loader/volatile-update` events, ensuring live changes from UI cards apply immediately to disk retention logic without service restart.

### 16.3 Zero-Leakage Invariant in Scanner & Findings Evidence (#171, #172)
- **Sanitized Diff Findings**: Removed raw cleartext `raw: val.slice(0, 80)` attribute from `scanSecrets` hits in `lib/guards/secrets.js`.
- **Masked SAST & Prompt-Injection Evidence**: Hardcoded passwords (`SAST-HARDCODED-PASS-001`) and embedded tokens in `lib/diff-gate/sast.js` and `prompt-injection.js` are redacted in the generated `evidence` line, guaranteeing that no plaintext secrets leak into persistent JSONL or `/audit` HTTP output.

### 16.4 Precise Tool Matching & False-Positive Elimination (#173)
- Replaced broad substring matching (`name.includes('file')`, `name.includes('write')`) with strict regex matching (`isCommandTool`, `isFileReadTool`, `isFileWriteTool`).
- Tools such as `profile`, `list_fs`, `rewrite` are excluded from false-positive interception.

### 16.5 Safe Regex Compilation & ReDoS Guard (#175)
- User-supplied patterns in `customBlockedCommands` and `sensitivePathPatterns` are validated and cached in an LRU Map via `getSafeRegExp`.
- Patterns exceeding 256 characters or containing catastrophic nested quantifiers are rejected with debug diagnostics.

### 16.6 Memory-Bounded Log Consumption & Inverted Turn Filter Fix (#174, #176, #69)
- `AuditRecorder.readAll(options)` bounds memory consumption via `maxRecords` and stream-level `sessionId` filtering.
- `buildBill` filters by `since` and `turnEnds` prior to applying `limit` slicing. The turn window filter evaluates both in-flight turns (`time > lastEnd`) and completed turns (`prevEnd < time <= lastEnd`).

### 16.7 HTTP Route Decoupling & Façade Hygiene (#177, #178, #179, #182)
- Extracted HTTP routes (`/dsh-shadow-auditor/audit`, `/events`, `/export`) and trusted request verifiers into `lib/routes.js`, reducing `lib/index.js` to strictly < 500 lines.
- `/events` and `/export` query parameters (`limit`) are clamped against `NaN` with `[1, 200]` and `[1, 5000]` boundaries. Uncaught errors in `/export` return sanitized `{ error: 'Failed to generate audit export' }` rather than leaking internal exception messages.
- Removed duplicated `debugFailure` method definition in `AuditRecorder`.

## 17. Command Guard Hardening & Evasion Defense (#68, #81, #82, #83, #106, #107)

### 17.1 Zero-Width & Homoglyph Normalization (#82)
- **Fast-path Exit**: Pure printable ASCII strings bypass normalization with zero allocation overhead.
- **Invisible Character Stripping**: Strips zero-width characters and directional marks (`\u200B`–`\u200D`, `\uFEFF`, `\u2060`, `\u00AD`, `\u200E`, `\u200F`, `\u202A`–`\u202E`).
- **Fullwidth Conversion**: Maps fullwidth ASCII (`\uFF01`–`\uFF5E`) and fullwidth spaces (`\u3000`) to standard ASCII characters.
- **Homoglyph Transliteration**: Normalizes Cyrillic, Greek, and other visual lookalikes to Latin equivalents (e.g., Cyrillic a, c, e, o, p, x, y to Latin equivalents) without introducing raw Cyrillic literals in `lib/` (using Unicode escape sequences).

### 17.2 Hidden Base64 Payload Inspection (#83)
- **Payload Extraction**: Detects Base64 tokens in shell arguments (PowerShell `-EncodedCommand` / `-enc`, `base64 -d`, `openssl enc -d -base64`, `b64decode()`, and generic Base64 tokens).
- **Safe Bounded In-Memory Decoding**: Decodes candidate tokens (up to 4 tokens per command, 16–4096 bytes) with UTF-8 and UTF-16LE validation.
- **Recursive Inspection**: Non-recursive subscan (`_isSubscan: true`) passes decoded payloads to `findDangerous()`, detecting nested destructive commands or exfiltration and tagging them as `(hidden in base64 payload)`.

### 17.3 Cross-Platform PowerShell & cmd.exe Syntax Analysis (#106)
- **PowerShell Cmdlets & Aliases**: Supports `Remove-Item` and aliases (`ri`, `rmdir`, `rd`, `erase`, `del`) along with parameters (`-Recurse`, `-r`, `-Force`, `-Path`, `-LiteralPath`).
- **Windows cmd.exe**: Supports `rd /s /q`, `rmdir /s /q`, `del /s /f`, and `erase /s`.
- **Process Termination & System Commands**: Expands `DANGEROUS_PATTERNS` to cover Windows `Stop-Process`, `spps`, `taskkill /f`, and `reg delete ... /f`.

### 17.4 Static Environment Variable Expansion for Path Targets (#107)
- **`resolveEnvToken(token)`**: Recursively expands `~`, `$HOME`, `%USERPROFILE%`, `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, `$env:VAR`, and `${VAR}` into canonical filesystem paths before performing workspace and protected system prefix checks.
- **Prefix Guard Enforcement**: Unconditionally blocks destructive commands targeting `$HOME/.dsh`, `%USERPROFILE%/.ssh`, or `%TEMP%/dsh-subprocess-*`.

### 17.5 Embedded URL Credentials Masking & Interception (#81)
- **Redaction Invariant**: `lib/redact.js` masks embedded credentials in URLs (`https://user:password@host/path`) to `https://***:***@host/path` across all audit records and evidence.
- **Guard Interception**: `findDangerous()` detects embedded URL credentials, permitting original command execution while dispatching non-blocking security alerts and sanitized audit logs.

### 17.6 Single-Pass Stage Partitioning & Regex Caching (#68)
- **Skip Redundant Pass**: If `segments.length <= 1`, per-stage checks are omitted since the full-command pass already evaluated all patterns.
- **Global vs. Stage Separation**: Global rules (`checkWorkspaceEscape`, `checkProtectedForcePush`) execute once on the composite command rather than repeating per pipeline segment.
- **Custom Pattern Caching**: Pre-compiles and caches custom regex blocklists using `getSafeRegExp` LRU cache.

## 18. Lifecycle Hooks & Interception Engine (#108, #109, #110, #111, #124, #125)

### 18.1 Guaranteed Priority Hook Registration via `prepend` (#125)
- All security-critical lifecycle event listeners (`tools/guard`, `tools/pre-execute`, `tools/post-execute`, `agent/pre-step`) are registered with `{ prepend: true }`.
- Guarantees execution at the head of the Cordis handler pipeline before third-party extension handlers execute.

### 18.2 Unconditional Critical Threat Blocking (`secretBlockCritical`) (#124)
- Introducing `secretBlockCritical: boolean` (default: `true`) in plugin configuration schema.
- When enabled, high-severity destructive system commands (e.g. root filesystem destruction, disk formatting) and critical credential leaks unconditionally trigger a hard block (`status: blocked`), completely bypassing lenient audit-only modes (`shellGuardMode: 'audit_only'`, `diffGateMode: 'warning'`).

### 18.3 DSH User Approval Integration & `ask` Mode (#108)
- On suspicious commands or elevated risks where `shellGuardMode` or `approvalMode` is configured for user interactive confirmation, returns `{ kind: 'ask', reason, displayReason }` in `tools/pre-execute`.
- Seamlessly interoperates with `ctx.approval` (`ApprovalService`) if available, presenting an interactive authorization prompt before dispatch.

### 18.4 Multi-Surface Lifecycle Interception Architecture (#109)
- Comprehensive multi-surface coverage spanning all four operational boundaries:
  1. `agent/pre-step`: Inspects user prompt payloads before LLM step execution.
  2. `tools/pre-execute` / `tools.guard`: Validates tool dispatch and command parameters.
  3. `tools/post-execute`: Sanitizes execution outcomes and command outputs.
  4. `tools/result`: Lossless persistent telemetry and risk evaluation tracking.

### 18.5 Pre-Filtering Incoming User Prompts (`agent/pre-step`) (#110)
- Scans incoming message content blocks on `agent/pre-step` for prompt-injection, adversarial jailbreaks, and system override attempts.
- Rejection halts execution early (`{ kind: 'reject' }`), preventing adversarial payloads from entering model context.

### 18.6 Tool Result Sanitization & Output Redaction (`tools/post-execute`) (#111)
- Intercepts raw tool outputs in `tools/post-execute`.
- Inspects text content blocks for exposed high-entropy secrets and sensitive infrastructure tokens.
- Automatically redacts identified secrets using `maskSecret()` before model context ingestion, returning `{ kind: 'accept', content: sanitizedBlocks }`.
