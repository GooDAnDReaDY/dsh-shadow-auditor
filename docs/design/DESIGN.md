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