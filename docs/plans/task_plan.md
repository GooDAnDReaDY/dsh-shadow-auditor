# Техническое задание и план реализации: dsh-shadow-auditor

## Goal
Фоновый аудит безопасности для DSH: детект утечек секретов + хардкод путей + деструктивных команд до подтверждения. Переиспользует паттерны `dsh-approval-gate`, не дублирует его guard, а расширяет UI-badge.

## 1. Цели и назначение
Обеспечение безопасности и чистоты кодовой базы: фоновое выявление утечек секретов, хардкода персональных путей и блокировка деструктивных терминальных команд до их подтверждения.

## 2. Архитектура решения
- **Модуль `SecretScanner` (`lib/guards/secrets.js`)**: pure regex-сканер API-ключей/токенов/приватных ключей + infra-путей (`/home/`, `/mnt/`, IP). Функция `scanSecrets(text): {level, hits}`.
- **Модуль `CommandSafetyGuard` (`lib/guards/command.js`)**: reuse `DANGEROUS_PATTERNS` из `dsh-approval-gate` + `--force`/`curl|bash` паттерны. Pure `findDangerous(cmd)`.
- **Интеграция с хуком `approval/asked`**: слушатель `ctx.events.on('approval/asked', ...)` enriches модалку badge Green/Yellow/Red (не `guard`, чтобы не конфликтовать с approval-gate).
- **Tools**: 3 tool-а оборачивают те же pure-функции.
- **Client**: один `lib/client.js` — `settings.plugin.item` карточка + badge overlay.

## Decisions Made
| Решение | Почему | Альтернатива отклонена |
|---------|--------|------------------------|
| Reuse паттернов approval-gate, не зависимость | Паттерны — 7 regex, зависимость тянет цикл | `npm install approval-gate` |
| Pure функции без классов | Тестируется без cordis/harness, `node --test` | Класс `SecretScanner` с методами |
| Не ставить `ctx.tools.guard` в shadow-auditor | Уже есть approval-gate; двойной guard = двойной deny | Дублировать guard |
| Badge через `approval/asked` event, не слот `approval.dialog` без проверки | Слот может отсутствовать в сборке ядра | Жёсткая регистрация слота |
| Энтропию отложить | Regex покрывает 95%, энтропия шумит | Сразу считать Shannon |

## 2.1 Проверяемость
- `lib/guards/*.js` — без `ctx`, импорт только Node, тесты `node --test` без сети/harness.

## 3. Декомпозиция задач (Work Breakdown Structure)

### Phase 1 — Backend Guard Engine (pure, без cordis)
- [ ] **1.1 `SecretScanner` (lib/guards/secrets.js)** — сигнатуры OpenAI/Anthropic/Gitea/GitHub/AWS/JWT/Private Keys, infra-пути, IP. Status: pending
- [ ] **1.2 `CommandSafetyGuard` (lib/guards/command.js)** — реюз DANGEROUS_PATTERNS из approval-gate + `--force` (git/pnpm/dsh), `curl|bash`, `mkfs/dd/chmod 777`. Status: pending
- [ ] **1.3 Уровни риска** — `green` (чисто), `yellow` (путь/IP без секрета), `red` (секрет или dangerous cmd). Status: pending

### Phase 2 — Agent Tools (host)
- [ ] **2.1 `shadow_auditor_scan_diff`** — `scanSecrets(diff)` → `{level, hits}`. Status: pending
- [ ] **2.2 `shadow_auditor_check_command`** — `findDangerous(command)` → `{blocked, hit}`. Status: pending
- [ ] **2.3 `shadow_auditor_rules_list`** — возвращает активные regex (имена, не значения). Status: pending
- [ ] **2.4 `ctx.events.on('approval/asked')` enrich** — вычисляет уровень и кэширует для badge. Status: pending

### Phase 3 — Frontend Web UI (client.js)
- [ ] **3.1 Settings card `settings.plugin.item` (key=NS)** — 3 тоггла + список правил read-only, статус snapshot `loading/unavailable/ready` (проверка!). Status: pending
- [ ] **3.2 Shield Badge** — читает кэш последнего `approval/asked`, рисует 🟢/🟡/🔴 в модалке approval (если слот отсутствует — fallback overlay в `slots`). Status: pending
- [ ] **3.3 Стили** — префикс `sa-`, только CSS-переменные `var(--dsw-*)`, карточка свёрнута по default, Chevron ядровый. Status: pending

### Phase 4 — Тестирование и надежность
- [ ] **4.1 Unit `node --test` — секреты** — по 1 кейсу на каждый тип (8+) + JWT + private key. Status: pending
- [ ] **4.2 Unit — ложноположительные** — `example.com`, `AKIAIOSFODNN7EXAMPLE`, `sk-test` не триггерят. Status: pending
- [ ] **4.3 Unit — команды** — `rm -rf`, `systemctl stop`, `psql ... DROP`, `echo > .env`, `curl | bash` блокируются, `systemctl is-active` проходит. Status: pending
- [ ] **4.4 Smoke** — `npm test` зелёный, `grep -r "192.168|/home/|/mnt/|file:"` чист. Status: pending

## 4. Next Step
Один next: создать Gitea issue `M: shadow-auditor guard engine + tools + badge (reuse approval-gate)` (type/security, scope/*, labels канон), затем branch `feat/shadow-auditor-guard` от `origin/main`, worktree, реализация Phase 1 pure-функций.

## Errors Encountered
| Error | Attempt | Resolution |
|-------|---------|------------|
| dsh-approval-gate локально пустой (`only .worktrees`) | 1 | Взяли исходник через Gitea API `contents/lib/index.js` |
| `print` с `⛔` падает под cp1251 в PowerShell | 1 | Использовали `backslashreplace` при выводе |

## Verification Checklist (перед PR)
- [ ] `npm test` — все 4 группы тестов зелёные
- [ ] `grep -R "192\.168\|/home/\|file:" lib/ README.md` — пуст (обезличенность)
- [ ] `package.json` name === `cordis.patch.yml` name === `client.js` id
- [ ] Settings card — статус snapshot проверяется, не значение
- [ ] Хуки React выше return, слот `locale: NS`, ключ `key: NS`
- [ ] `approval/asked` слушатель обернут в `ctx.effect`, уборщик возвращает