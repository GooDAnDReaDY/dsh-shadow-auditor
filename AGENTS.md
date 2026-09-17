# AGENTS.md

Этот файл дополняет корневой `A:\mnt\external\Project\DEV\AGENTS.md` и
содержит только правила и факты, специфичные для данного проекта.

При противоречии с корневыми правилами агент обязан остановиться, описать
противоречие и согласовать дальнейшие действия с пользователем.

## Product / Purpose

- Проект: `dsh-shadow-auditor`
- DEV: /mnt/external/Project/DEV/dhsplugins/dsh-shadow-auditor. `/mnt/external/Project/DEV/dsh-shadow-auditor`

## Package policy (только для DSH-плагина)

- Все плагины проектируются публичными с первого коммита.
- Имя пакета: `@goodandready/dsh-shadow-auditor`.
- До прямой команды владельца «публикуем» пакет не публикуется в GitHub/npm.
- Первая публичная версия может быть текущей внутренней версией, например
  `0.2.19`; пропущенные версии не выпускаются и не воспроизводятся.
- Другие registry и альтернативные package-scope не используются.
- OPT: not applicable; DSH runtime installs immutable registry package. not applicable; production uses the immutable package in the DSH profile
- Назначение: DSH plugin for background security auditing, sensitive data and shell command risk.
- Основные пользователи: DeepSeek Harness users and agents.
- Основной результат работы продукта: security findings and command risk classification.
- Текущий статус: unknown (source repository active; runtime was not checked)
- Статус проверен: 17.09.2026, Gitea main/worktree/issue metadata; runtime health not checked

Статус нельзя определять на глаз. Если он не проверен фактически, указывать
`unknown`.

## Project Index (`index.md`)

- `index.md` создан и проверен: да (в этом worktree)
- Назначение и текущий статус: security auditing for DSH; source and Gitea main checked 2026-09-17; runtime health not checked.
- DEV / OPT: /mnt/external/Project/DEV/dhsplugins/dsh-shadow-auditor; no dedicated OPT checkout, DSH profile uses registry package.
- Точки запуска и пользовательские entry points: lib/index.js host plugin, lib/client.js client UI.
- Основные компоненты: host lifecycle, client UI, command/secrets guards and diff gate. lib/guards/command.js, lib/guards/secrets.js, lib/diff-gate/; docs/design/DESIGN.md.
- Проверенные команды build / test: npm test runs node --test test/*.test.mjs.
- Штатный deploy и ссылка на `deploy.sh`:
- Дата и способ последней проверки: 2026-09-17, SSH MiniAI; Gitea issues, main/worktree and package/test metadata.

`index.md` — краткая навигационная карта проекта. Он содержит только
подтверждённые факты и ссылки; не копирует полностью этот файл, CodeWiki или
исходный код.

## Essential Files
### Единая структура проектной документации

В каждом проекте должна существовать папка `docs/` — единственное место для
подробной проектной документации. Документы не создаются в корне проекта, в
исходниках, `scripts/`, `config/`, `deploy/` или других произвольных
каталогах.

Минимальная структура:

- `docs/plans/` — живые планы medium/complex-задач и планы реализации;
- `docs/audit/` — результаты аудита, безопасности, зависимостей,
  `npm audit`, `npm-check-updates` и ревизий;
- `docs/architecture/` — baseline, архитектура и схемы;
- `docs/adr/` — принятые архитектурные решения;
- `docs/deployment/` — проверенные инструкции и чек-листы deploy;
- `docs/testing/` — тестовые стратегии, сценарии и результаты;
- `docs/research/` — reuse-first-исследования и анализ готовых решений.
- `docs/design/DESIGN.md` — обязательный дизайн-контракт проекта; создаётся и
  поддерживается через skill `project-design-contract`.

Если подпапка нужна, агент создаёт её только в назначенном Git worktree
вместе с первым документом. Пустые каталоги не создавать.

Правила хранения:

- Перед созданием документа определить его категорию и поместить файл в
  соответствующую подпапку `docs/`.
- Не создавать новые подробные `PLAN.md`, `ARCHITECTURE.md`, `AUDIT.md`,
  `DEPLOYMENT.md` и подобные файлы в корне или рядом с кодом.
- `AGENTS.md` и обязательный корневой `index.md` — служебные навигационные
  файлы workflow, а не место для подробной документации. В них оставлять
  только краткие подтверждённые факты и ссылки на `docs/`.
- Проектный `README.md`, если он является документацией, также должен быть
  краткой навигацией со ссылками на `docs/`; новые подробные разделы в корень
  не добавлять.
- Планы medium/complex хранить в `docs/plans/` и синхронно отражать в
  Gitea/Kanban и Memory Brain. Рабочие файлы planning-with-files в
  `.planning/<issue>-<slug>/` остаются артефактами процесса и не заменяют
  документацию в `docs/`.
- Ссылки использовать относительно: `@docs/architecture/baseline.md`,
  `@docs/plans/184-feature.md`. Дубли документов не создавать.

Если старые правила или файлы проекта противоречат структуре, агент не удаляет
и не перезаписывает их молча: регистрирует/обновляет Gitea issue, описывает
конфликт и предлагает план миграции.


### Обязательный documentation gate для каждого коммита

Перед каждым коммитом агент обязан актуализировать всю документацию, затронутую
изменением:

- соответствующие файлы в `docs/`;
- краткий `index.md`, если изменились назначение, статус, команды, зависимости,
  структура или deploy;
- проектный `AGENTS.md`, если изменились правила, ограничения или решения;
- статью продукта в Wiki/Obsidian;
- устойчивый факт о коммите, результате и проверках в Memory Brain.

Документация должна войти в тот же коммит, что и изменение, либо быть
подготовлена в том же логическом commit-пакете. Сразу после коммита агент
проверяет, что документация соответствует фактическому SHA и результату, и
обновляет Wiki/Obsidian и Memory Brain. Documentation-only commit также
проходит эту проверку; пустые коммиты для имитации обновления запрещены.

Если агент не может обновить Wiki/Obsidian или Memory Brain, он не скрывает
это: регистрирует Gitea issue с причиной, сохраняет факт в доступном журнале
workflow и сообщает о blocker.



- `@path/to/file` — краткое назначение.

Указывать только действительно важные файлы. Не добавлять полное дерево
проекта или очевидный список содержимого каталогов.

## Key Architecture

- Основные компоненты:
- Архитектурный подход: Cordis host plugin with separate client portion and local guard modules.
- Основные API и интерфейсы: plugin context events/guards and command classifier exports.
- Источник истины для данных: runtime event inputs; no project-owned database.
- Источник истины для конфигурации: DSH plugin configuration and checked-in schema/defaults.

## Project Baseline (для medium / complex)

- Цель и пользователи:
- Архитектурная схема / ссылка на docs/architecture:
- Границы компонентов и интерфейсы:
- Зависимости и источники истины для данных/конфигурации:
- Риски и ограничения:
- Критерии успеха:
- Текущее состояние тестов:
- ADR / зафиксированные архитектурные решения:
- Architecture baseline создан по PROJECT-ARCHITECTURE-TEMPLATE.md:
- ADR создаются по PROJECT-ADR-TEMPLATE.md в docs/adr:

Заполняется архитектором перед новым проектом, крупной feature, рефакторингом
или другим complex изменением. Только подтверждённые факты и принятые решения.

## Reuse And Existing Solutions

- Похожие решения внутри проекта: existing command and secret guards in lib/guards/.
- Что найдено в `/mnt/external/Project/_code_library`:
- Что найдено на GitHub / в open-source: bash-parser is stale; sh-syntax WASM exceeds the 262144-byte per-file package cap.
- Что найдено в package registries: no suitable maintained parser dependency confirmed for #56.
- Что форкаем / адаптируем: nothing.
- Почему пишем своё, если готовое не используется: #56 needs narrow pipeline-stage classification; candidates fail maintenance or package constraints.

Этот раздел заполняется фактами после поиска. Не писать с нуля без проверки
готовых решений.

## Constraints (MUST NOT)

### Cleanup после завершения

- После merge и проверки очищать только собственные временные артефакты задачи
  и уже merged ветку/worktree, если они больше не нужны.
- Нельзя использовать `git clean`, `git branch -D`, force delete, удалять
  чужие/неясные файлы, ветки, worktree, runtime-логи, БД или конфиги.
- При неясном владельце/назначении артефакта ничего не удалять: зарегистрировать
  проблему в Gitea и согласовать действия с пользователем.

- Запрещено:
- Изменения, требующие явного согласования пользователя:
- Локальная работа на ПК: запрещена; все проектные команды, скрипты, временные
  файлы, тесты и логи выполняются/хранятся только на сервере `192.168.1.111`.
- Local-to-server staging: запрещён; не создавать скрипты в `C:\...\Temp` и не
  передавать их через `scp`. Временные server-side файлы допускаются только при
  необходимости и должны удаляться после использования.
- Единственные корневые папки проекта: DEV `/mnt/external/Project/DEV/<project>`
  и OPT `/opt/<project>`. Clone, ручные копии каталогов, test-copy,
  shadow/sandbox/staging/backup-папки запрещены.
- Корневой checkout `/mnt/external/Project/DEV/<project>` (включая `main`
  или integration branch) — read-only: в нём запрещены любые изменения,
  генерация артефактов, тесты, сборка и Git-команды, меняющие рабочее дерево.
- Единственное место работы с записью: Git-managed worktree внутри
  `/mnt/external/Project/DEV/<project>/.worktrees/<branch>`, один
  исполнитель на worktree/ветку. В нём выполняются правки, тесты, QA, сборка,
  отладка, commit и merge.
- База нового worktree — только свежий `origin/main`, не локальный `main` DEV-root. Разрешённое исключение в DEV-root: `git-<agent> -C /mnt/external/Project/DEV/<project> fetch --no-tags origin main` (обновляет remote ref без checkout/правок файлов), затем `git-<agent> -C /mnt/external/Project/DEV/<project> worktree add -b <branch> .worktrees/<branch> origin/main`.
- Если fetch/remote/ref невалидны или branch занят — STOP, зафиксировать расхождение в Gitea/Kanban и согласовать действия. Не создавать ветку от stale-main и не менять remote молча.
- Если назначенный worktree отсутствует, занят другим агентом, грязный или
  связан не с той веткой, агент останавливается, фиксирует проблему в
  Gitea/Kanban и ждёт решения; ручные копии создавать нельзя.

Этот раздел содержит только жёсткие проектные ограничения. Допустимые
исключения должны быть указаны явно.

## Conventions

- Именование: follow existing JavaScript module/test conventions and Conventional Commits.
- Организация кода: source in lib/, tests in test/, product docs in docs/.
- Проектные соглашения: preserve the explicit npm package allowlist and add guard regression tests.
- Обычный способ реализации изменений: modify the smallest relevant guard and tests; document user-visible behavior in EN/ZH.

Этот раздел содержит принятые способы работы, а не абсолютные запреты.

## Locked Decisions

- `<ДД.ММ.ГГГГ>` — `<принятое решение>`
  - Причина:
  - Основание:
  - Условие пересмотра:

Зафиксированное решение нельзя молча переоткрывать или заменять другим.

## Dependencies

- Базы данных:
- Внутренние сервисы:
- Внешние API:
- Очереди и фоновые процессы:
- Критичные runtime-зависимости: DSH/Cordis host services and declared npm dependencies.

## Build And Run

- Установка: npm install --no-package-lock --ignore-scripts for local checks; runtime uses a registry package.
- Сборка: no separate build command found.
- Запуск в DEV: no standalone service; integration uses isolated DSH test profile.
- Необходимые сервисы: isolated DSH test profile on MiniPC for pre-publication validation.
- Проверка успешного запуска: plugin loads in isolated profile and applicable smoke tests pass.

Команды указывать только после фактической проверки по проекту.

## Testing

- Обязательные проверки: focused guard tests, full npm test and package allowlist/preflight.
- Unit-тесты: npm test.
- Integration-тесты: install packed candidate in isolated MiniPC DSH profile before publication.
- Lint/typecheck: no separate command found.
- Критерии готовности: regression matrix passes and existing dangerous-command protections remain effective.

### Definition of Ready (medium / complex)

- Ожидаемый результат и измеримые критерии готовности:
- Границы задачи и затрагиваемые компоненты:
- Риски:
- Reuse-first: что найдено и почему выбран этот вариант:
- Blast radius: результат codegraph/семантического поиска:
- План тестов и проверок до реализации:

Без заполненного DoR реализация medium/complex не начинается. Если codegraph
или семантический поиск недоступен, это фиксируется как ограничение в Gitea.

### Definition of Done

- Реализация завершена и закоммичена:
- План проверок выполнен, результаты приложены:
- Независимый review: PASS / FAIL, ссылка на доказательства:
- Документация/комментарии в коде обновлены:
- Готовность deploy подтверждена:

### Node / npm Dependencies (если применимо)

- `npm audit`: команда, дата и результат последней проверки:
- `npm-check-updates`: команда, дата и результат read-only проверки:
- Связанные Gitea issues по уязвимостям и dependency updates:

`npm audit fix`, `npm audit fix --force`, `ncu -u` и автоматические массовые
обновления не являются частью обычной задачи. Они выполняются только отдельным
issue/веткой после проверки совместимости и полного набора тестов.

## Gitea Project Setup

- Gitea repository: goodandready/dsh-shadow-auditor.
- Main branch: main; work starts from fresh origin/main in a dedicated worktree.
- Issue #56 is active for this change. Other backlog issues remain separate unless the user groups them.
- Project boards, Kanban, leases and dispatcher workflows are not used.
- Follow root AGENTS.md: Gitea issue -> worktree/branch -> implementation/tests -> commit/push -> PR/review.
- Branch protection and mandatory CI checks were not verified.

## Commits, Versions And Releases

- Формат коммита: Conventional Commits, например `fix(command): scope sensitive writes per command`
- Допустимые commit types:
- Как связываются коммиты с Gitea issues (`Refs #...`):
- Один завершённый логический результат = один commit: да
- Текущая версия продукта:
- Planned / active milestone:
- Правило повышения `x.y.z_dd.mm.yyyy` для этого проекта:
- Gitea Release / protected tag: no release/tag in normal issue work; publication requires owner approval

Общее правило: агент работает в текущей линии `x.y` максимально долго. Для
обычных согласованных релизов меняется только `z`; переход второй цифры
`y` возможен исключительно после явного согласования пользователя. Количество
коммитов, фиксов, PR и предыдущих релизов не является основанием поднять `y`.
Если `z` достиг `99`, агент останавливается и согласует дальнейшую нумерацию.

Обычные коммиты не повышают версию продукта. Не использовать пустые сообщения
`wip`, `update`, `changes`, `misc`; не смешивать в одном коммите несвязанные
виды работ.

## Code Review

- Специфичные для проекта чеклисты:
- Дополнительные проверки качества:
- Проектные code review агенты (если есть):
- Пороговые значения (макс. строк в функции/файле, покрытие):
- Регрессионные сценарии:
- Независимый ревизор:
- Принимающий агент:
- Формат вердикта: только PASS / FAIL с SHA/diff/командами/результатами:

Ревизор не вносит молча исправления вместо исполнителя. При FAIL он возвращает
замечания исполнителю, после новой правки нужен повторный review. Исполнитель
не принимает собственный результат.

## Security Review

- Специфичные для проекта security-риски: command classification errors and sensitive-data false positives/negatives.
- Чувствительные данные и эндпоинты:
- Типовые уязвимости проекта: parser/segmentation bypasses and sensitive data disclosure through logs.
- Дополнительные security-проверки:
- Контакты / escalation path при находке:

## Data, Database And Configuration

- Используемые БД:
- Важные конфиги: plugin schema/configuration and package allowlist in package.json.
- Правила миграции: no database migrations.
- Правила резервного копирования:
- Копии проекта/БД/конфигов по умолчанию: запрещены; если предполагаются,
  требуется отдельное явное решение пользователя:
- Обязательные проверки целостности:
- Проектные операции, требующие согласования:

## Deployment

- DEV:
- OPT:
- Порт: none owned by this plugin.
- Штатный способ деплоя: DSH package workflow; no project deploy script.
- Необходимые действия перед деплоем:
- Проверки после деплоя:
- Критичные показатели для сравнения до и после деплоя:

### `deploy.sh`

- Скрипт существует и tracked в Git: нет; deployment использует опубликованный package и согласованный DSH workflow
- Назначение и подтверждённый способ запуска:
- Какой branch/SHA он разворачивает:
- Затрагиваемые сервисы:
- Pre-deploy и post-deploy проверки:
- Какие операции требуют отдельного согласования:

`deploy.sh` — единственный штатный project-specific entry point deploy из
Gitea в OPT. Он не содержит секретов, не делает ручную синхронизацию, reset,
неявные миграции или изменение config/DB. Создавать заглушку запрещено.

Способ деплоя, скрипты и команды указывать только после фактической проверки.
Деплой выполняется по корневому процессу и только после подтверждения
пользователя.

## Handoff

- Шаблон: PROJECT-HANDOFF-TEMPLATE.md
- Где ведётся handoff: Gitea issue and PR; Kanban is not used.
- Какие проверки и ссылки обязательны для этого проекта:
- Кто принимает handoff: task owner/user.

Handoff обязателен при передаче, блокировке, смене исполнителя и окончании
сессии с незавершённой работой. Он не заменяет Memory Brain и закрывающий
комментарий issue.

## Known Issues And Limitations

- Подтверждённые ограничения:
- Связанные issues: #56 active; #47-55 are separate backlog; #50 tracks public GitHub tree sanitization.
- Известный технический долг:

Неподтверждённые гипотезы сюда не добавлять: они относятся к открытым вопросам.

## Open Questions

- Неподтверждённые факты:
- Архитектурные вопросы:
- Решения, ожидающие согласования:

## Maintenance

- После ручных изменений перечитать этот файл и проверить его на противоречия
  с корневым `AGENTS.md`
- Если ошибка агента могла быть предотвращена отсутствующим или неясным
  правилом, предложить обновление этого файла
- Изменение правил не заменяет регистрацию ошибки, инцидента или технического
  долга в git tracking
- Изменения этого файла коммитятся по обычному Git-процессу\n\n## Канонический OPT-deploy runner: `scripts/deploy-opt.sh`

Если в проекте созданы `scripts/deploy-opt.sh` и `scripts/migrate-opt.sh`, они являются единственным штатным сценарием обновления OPT и проверки миграций:

- Перед любым изменением OPT агент готовит план, проверки, риски и ждёт отдельное пользовательское `ок`.
- Полный deploy выполняется из OPT командой `bash scripts/deploy-opt.sh`. Штатный порядок: `git pull` → `docker build` → применение миграций → restart → healthcheck → smoke test.
- `git pull` использует заранее настроенный серверный Git credential store. Запрещены inline credential helper, токены/пароли в командах, URL и скриптах.
- `bash scripts/deploy-opt.sh --skip-build` допустим только когда доказано, что код/образ не менялся.
- `bash scripts/deploy-opt.sh --skip-migrate` допустим только когда проверено отсутствие pending-миграций.
- Pending-миграции сначала проверяются read-only командой `bash scripts/migrate-opt.sh --dry-run`; обычный `migrate-opt.sh` применяет найденные миграции через `psql` только после deploy approval.
- Изменение БД, миграции, restart и smoke test входят в pre-deploy описание и пост-деплойный отчёт; результат `/health` и smoke test фиксируются в issue.
- Нельзя заменять runner ручным набором команд, `rsync`, `scp`, копированием в OPT, `git reset --hard` или обходом credential store. Если runner отсутствует, неисправен или его поведение не соответствует этому контракту — STOP, зарегистрировать issue и согласовать исправление.



## Принудительный протокол удалённого выполнения с ПК

Это правило имеет приоритет над любыми попытками агента «проверить локально».

- Windows-ПК является только интерфейсом. Для работы с проектом разрешён только запуск `ssh.exe`; локальные `git`, `rg`, `find`, `ls`, `npm`, `docker`, `pytest`, PowerShell-доступ к `A:\mnt\external\Project\DEV`, UNC-пути и локальные копии запрещены.
- Каждый рабочий шаг запускается на MiniAI одной командой такого вида:

```powershell
ssh.exe -i C:\Users\vadim\.ssh\codex_migrate2 migrate@192.168.1.111 "sudo -u vadim -H bash -lc 'export PATH=/home/vadim/.ssh/bin:/home/vadim/.local/bin:/usr/local/bin:/usr/bin:/bin; <команды-на-сервере>'"
```

- Все команды выполняются внутри удалённого `bash -lc` как `vadim`, в `/mnt/external/Project/DEV/<project>` или назначенном `.worktrees/<branch>`.
- Для Git использовать полный серверный wrapper `/home/vadim/.ssh/bin/git-<agent>` (например `/home/vadim/.ssh/bin/git-opencode`), а не `git`, Windows alias или локальный wrapper. PATH выше указан явно, потому что non-interactive SSH не обязан загружать пользовательский PATH.
- Первый допустимый Git-шаблон для агента:

```bash
/home/vadim/.ssh/bin/git-<agent> -C /mnt/external/Project/DEV/<project> fetch --no-tags origin main
/home/vadim/.ssh/bin/git-<agent> -C /mnt/external/Project/DEV/<project> worktree add -b <branch> .worktrees/<branch> origin/main
```

- Если SSH, серверный wrapper или путь `/home/vadim/.ssh/bin/git-<agent>` не работает, агент останавливается и регистрирует инфраструктурный issue. Нельзя переходить на локальный Git, bare `git`, UNC/network path, другой ключ, ручное создание wrapper или копирование проекта.
- Сообщения «`git-<agent> не найден`», «SSH key не найден на ПК» и «корневой checkout доступен локально» не являются основанием для обхода: сначала проверить PATH и wrapper внутри удалённой команды, затем зафиксировать blocker.



## Автономное выполнение порученного пула

- Если пользователь поручил выполнить пул issue/задач, агент сам проходит worktree → реализация → проверки → commit → push → следующая задача без запроса разрешения на каждый обычный шаг.
- Остановиться можно только при реально блокирующем факторе или когда требуется мнение пользователя по решению, меняющему направление, архитектуру, риски или итоговый результат. К блокирующим факторам относятся safety-stop, обязательное явное разрешение на опасную операцию/deploy и внешний blocker, без которого продолжение невозможно. Мелкие вопросы агент решает сам по workflow. Результат каждого завершённого issue фиксируется сразу.
- Автономное выполнение не разрешает самовольные разрушительные действия: нельзя удалять функционал, файлы, ветки, данные, конфиги, миграции, сервисы или выполнять rollback/reset/force-операции, если пользователь прямо не попросил именно это действие.


## Project-Specific Facts (verified 2026-09-17)

- Project: `dsh-shadow-auditor`; DEV root: `/mnt/external/Project/DEV/dhsplugins/dsh-shadow-auditor`.
- Package: public `@goodandready/dsh-shadow-auditor`; current main source version observed in package.json is `0.2.9`. Do not change package identity or version as part of issue #56.
- Product: host/client DSH plugin for background security auditing, sensitive-data findings and command risk detection.
- Components: `lib/index.js` host registration, `lib/client.js` client UI, `lib/guards/command.js` command classifier, `lib/guards/secrets.js` secret scanning, `lib/diff-gate/` change inspection.
- Production uses an immutable registry package in the DSH profile; no project-specific `/opt/dsh-shadow-auditor` checkout or deployment script was found.
- Tests: `npm test` runs `node --test test/*.test.mjs`; package tests are required before PR.
- Test server: use the isolated DSH test profile and never remove, update or reconfigure `dsh-lanmode`.
- Branch/worktree for issue #56: `fix/shadow-auditor-command-false-positives` under `.worktrees/fix/shadow-auditor-command-false-positives`.
- Issue #56 changes stay limited to the command guard, its tests, and relevant product/design docs. Other open issues are separate work.
- Internal `AGENTS.md`, `index.md`, `.planning/` and `docs/plans/` are not npm package files; do not push them to the public GitHub tree. The existing Gitea issue #50 tracks sanitizing public GitHub source publication and must be resolved before any publication.
- Never alter production profile, service, credentials, settings or other plugins without separate authorization. No merge, deploy, version/tag or publication as part of this issue.
