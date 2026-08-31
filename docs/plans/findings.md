# Findings & Architectural Notes: dsh-shadow-auditor

## 2026-08-30 — Анализ dsh-approval-gate (reuse для CommandSafetyGuard)

**Источник:** `goodandready/dsh-approval-gate` @ `main` (2d41519), `lib/index.js` (3276b), private route `@goodandready-private/dsh-approval-gate`.

**Механизм:**
- `inject: ['tools']`, `ctx.tools.guard((execution) => string | undefined)` — возвращает строку = deny, `undefined` = pass.
- Проверяет только `execution.name === toolName` (default `bash`), берет `execution.arguments.command`.
- Логирует `console.warn` с усеченным хитом (140 chars), возвращает блокирующее сообщение на русском с `⛔` + инструкция "нужно явное `делай`".

**Паттерны DANGEROUS_PATTERNS (реюз 1:1 в shadow-auditor):**
1. `rm -rf` — `/\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+\S+/i`
2. `kill/pkill/killall` — `/\b(?:kill|pkill|killall)\b/i`
3. `systemctl stop/restart/...` — `/\bsystemctl\s+(?:stop|restart|disable|enable|mask|unmask|reboot|halt|poweroff|shutdown)\b/i`
4. `service X stop/restart` — `/\bservice\s+\S+\s+(?:stop|restart|force-stop|force-reload)\b/i`
5. DB destructive — `/(sqlite3|mysql|psql|pg_restore|mongo|mongosh|redis-cli|clickhouse-client).*?(ALTER|DROP|TRUNCATE|DELETE FROM|CREATE TABLE|DATABASE|INDEX)/i`
6. Write to .env — `/(?:\s(?:>>|>)\s|\|\s*tee\s+|\bsed\s+-i\b).*\.env\b/i`
7. Write to secret/token/credential/api_key/passwd — `/(?:\s(?:>>|>)\s|\|\s*tee\s+|\bsed\s+-i\b).*(?:secret|token|credential|api[_-]?key|passwd)\S*/i`

**Что добавить для shadow-auditor (расширение, не дублирование):**
- `--force` / `-f` без контекста rm — общий `/(?:^|\s)(?:--force|-f\b)/` но только для git/pnpm/npm/dsh — иначе шум.
- `rm -rf /`, `rm -rf ~`, `mkfs`, `dd if= /dev/`, `chmod 777`, `chown -R` — по 1 regex каждая.
- `curl | bash`, `wget | sh` — pipe-to-shell.

**Вывод reuse:** Копируем массив `DANGEROUS_PATTERNS` как базу, выносим в `lib/guards/command.js` (pure function `findDangerous(command): string|undefined`), покрываем тестами без cordis. Не тянем зависимость от `dsh-approval-gate`, только паттерны.

## SecretScanner — каталог сигнатур

**Проверенные источники (grep по существующим плагинам + OWASP):**
- OpenAI: `sk-[a-zA-Z0-9]{20,}` (+ `sk-proj-...`), Anthropic: `sk-ant-...`, Gitea: `gitea_...`, GitHub: `ghp_`, `gho_`, `github_pat_`, AWS: `AKIA[0-9A-Z]{16}`, GCP SA json, JWT: `eyJ[A-Za-z0-9_-]+\.eyJ...`, Private key: `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`
- Инфра-пути: `/(?:\/home\/\w+|\/mnt\/\S+|\/opt\/\S+|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)/` — но только если в diff есть `+` строка (added lines).
- Generic token entropy: `[A-Za-z0-9_\-]{32,}` с энтропией >4.2 — отложить (ponytail: regex достаточно, entropy если шум).

**Ложноположительные:** `example.com`, `sk-test`, `AKIAIOSFODNN7EXAMPLE` — добавить allowlist.

## Frontend — approval/asked хук

- DSH шлет событие `approval/asked` с `id, tool, reason` (см. dsh-plugin-authoring: `assistant/message`, `approval/asked`).
- Потоковая выдача ненадежна, но `approval/asked` — целый объект, можно `ctx.effect(() => ctx.events.on('approval/asked', handler))`.
- Shadow-auditor не должен `guard` (это делает approval-gate), а enriches: слушает событие, сканирует `execution.arguments` (command/diff), вычисляет уровень Green/Yellow/Red, инжектит badge в модалку через слот `approval.dialog` *если такой слот есть*, иначе — fallback в `slots` overlay. Проверить наличие слота read-only перед регистрацией.

## Архитектура Cordis — ловушки

- `ctx.inject(['settings'], (sctx) => ...)` дает другой контекст — использовать `sctx`.
- `ctx.effect` возвращает уборщика — обернуть все `guard` и `events.on`.
- Клиент: `window.__ModuleLoader__.load({ id, factory })`, `locale` обязателен в слоте, хуки React выше всех `return` (error 310).

## Решение по структуре файлов (ponytail)

```
lib/
  index.js            — apply(), регистрация tools + guard/event
  guards/
    secrets.js        — pure scanSecrets(text): {level, hits[]}
    command.js        — pure findDangerous(cmd): string|undef  (reuse approval-gate)
  client.js           — badge + settings card (один файл, без разбиения)
```

Без дополнительных абстракций: одна функция на файл, без фабрик/классов с одним методом.
