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
