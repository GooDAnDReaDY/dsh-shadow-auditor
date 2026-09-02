# 📦 @goodandready/dsh-shadow-auditor

<div align="center">

<h3>Фоновый аудитор безопасности, сканер утечек ключей и защита от деструктивных команд для DeepSeek Harness</h3>

<p align="center">
  <a href="https://www.npmjs.com/package/@goodandready/dsh-shadow-auditor"><img src="https://img.shields.io/npm/v/@goodandready/dsh-shadow-auditor.svg?style=for-the-badge&color=6366f1&labelColor=1e1b4b" alt="npm version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-10b981.svg?style=for-the-badge&color=10b981&labelColor=064e3b" alt="license"></a>
  <a href="https://github.com/topics/dsh-plugin"><img src="https://img.shields.io/badge/DSH-Plugin-8b5cf6.svg?style=for-the-badge&labelColor=2e1065" alt="DSH Plugin"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/Node-20%2B-f59e0b.svg?style=for-the-badge&labelColor=451a03" alt="Node version"></a>
</p>

<!-- Обязательная кнопка перехода на витрину всех проектов -->
<p align="center">
  <a href="https://goodandready.app/"><img src="https://img.shields.io/badge/Все_проекты_автора-goodandready.app-ff4500.svg?style=for-the-badge&logo=rocket&logoColor=white&labelColor=1a1a2e" alt="Все проекты автора"></a>
</p>

<p align="center">
  <a href="README.md"><b>🇬🇧 English</b></a> •
  <a href="README.ru.md"><b>🇷🇺 Русский</b></a> •
  <a href="README.zh.md"><b>🇨🇳 中文说明</b></a>
</p>

</div>

---

## ⚡ Обзор

**`dsh-shadow-auditor`** обеспечивает непрерывный фоновый аудит безопасности и защиту от выполнения опасных команд для агентов **DeepSeek Harness**.

При написании кода, редактировании файлов или запуске терминальных команд автономными агентами существует риск случайной утечки API-ключей, токенов доступа или выполнения разрушительных скриптов (`rm -rf /`, форк-бомб, случайной перезаписи системных файлов).

Плагин действует как внутрипроцессный фаервол безопасности, проверяя дифы кода на наличие секретов и блокируя деструктивные операции в терминале.

```mermaid
graph LR
    subgraph AgentExecution [Действия агента DSH]
        Agent[🤖 Агент: Пишет код / Запускает команду] --> Intercept{Перехватчик безопасности}
    end

    subgraph SecurityEngines [Ядро dsh-shadow-auditor]
        Intercept --> SecretScan[🔑 Сканер секретов и токенов]
        Intercept --> CmdGuard[🛡️ Фаервол терминальных команд]
    end

    subgraph Enforcement [Контроль и журнал]
        SecretScan -->|Безопасно| Pass[✅ Разрешить выполнение]
        SecretScan -->|Обнаружен секрет| Block1[⛔ Блокировка и маскирование токена]
        CmdGuard -->|Безопасно| Pass
        CmdGuard -->|Опасная команда| Block2[⛔ Блокировка и запрос подтверждения]
        Block1 --> AuditLog[📋 Журнал аудита безопасности]
        Block2 --> AuditLog
    end

    style AgentExecution fill:#1e1e2e,stroke:#89b4fa,stroke-width:2px,color:#cdd6f4
    style SecurityEngines fill:#181825,stroke:#cba6f7,stroke-width:2px,color:#cdd6f4
    style Enforcement fill:#11111b,stroke:#a6e3a1,stroke-width:2px,color:#cdd6f4
```

---

## ✨ Ключевые возможности

### 1. 🔑 Сканирование утечек ключей и паролей (`lib/guards/secrets.js`)
* Сканирование дифов на API-ключи, приватные сертификаты, RSA/SSH ключи и токены баз данных;
* Блокировка отправки конфиденциальных данных до фиксации в коммитах или передачи наружу;
* Автоматическая замена секретов на `[REDACTED]` в журналах.

### 2. 🛡️ Защита от опасных команд (`lib/guards/command.js`)
* Синтаксический анализ терминальных команд перед выполнением;
* Перехват опасных паттернов (`rm -rf /`, деструктивный `dd`, сброс баз данных, снос прав доступа);
* Требование явного подтверждения пользователя для рискованных сценариев.

### 3. 📋 Настраиваемые правила и панель Web UI (`lib/client.js`)
* Гибкое управление правилами безопасности;
* Индикатор статуса и журнал инцидентов безопасности в интерфейсе DSH.

---

## 🛠️ Инструменты агента (3 инструмента)

| Имя инструмента | Параметры | Описание |
|---|---|---|
| `shadow_auditor_scan_diff` | `diff: string` | Проверяет диф кода на наличие приватных ключей и токенов |
| `shadow_auditor_check_command` | `command: string` | Оценивает терминальную команду на безопасность перед запуском |
| `shadow_auditor_rules_list` | *(нет)* | Возвращает список активных правил безопасности и режимов |

---

## 📦 Быстрая установка

```bash
dsh plugin --profile web add @goodandready/dsh-shadow-auditor
```

---

## ⚙️ Пример конфигурации (`settings.yaml`)

```yaml
dsh-shadow-auditor:
  strictSecretScanning: true    # Блокировать выполнение при обнаружении ключей в коде
  blockDangerousCommands: true  # Блокировать разрушительные команды в терминале
  enableAuditBadge: true        # Отображать бейдж безопасности в интерфейсе и диалогах подтверждения
```

---

---

## 🔄 История версий

### v0.1.4 (Hotfix регистрации слота настроек)
* **Асинхронная регистрация слота (`settings.plugin.item`)**: регистрация карточки настроек переведена на `ctx.slots.inject`, что предотвращает ошибку загрузчика ядра при обращении к ещё не объявленному слоту (`slot is not declared`).
* **Запасной раздел (`settings.section`)**: добавлен автоматический fallback на персональный раздел настроек с таймером и очисткой через `ctx.effect`, если в текущей сборке DSH отсутствует слот карточек плагинов.

### v0.1.3 (Hotfix безопасности и стабильности)
* **Усиленный разбор цепочек команд (`findDangerous`)**: анализ составных терминальных выражений (`&&`, `||`, `;`, перенос строк) предотвращает обход фаервола разрешёнными подкомандами (`systemctl status && rm -rf /`).
* **Точное исключение секретов (`scanSecrets`)**: устранена ложная фильтрация боевых токенов и ключей, содержащих подстроку "example".
* **Автоматическое маскирование токенов (`maskSecret`)**: перехваченные секреты маскируются (`sk-pr...****...1234`) перед передачей в HTTP API и отображением в Web UI.
* **Неограниченное сканирование файлов**: снято ограничение на размер проверяемого файла (ранее первые 8 КБ), файлы любого размера проверяются полностью.
* **Корректный жизненный цикл Cordis**: регистрация инструментов изолирована в `ctx.effect` с автоматической очисткой при перезагрузке; исправлен контекст события `approval/asked`.
* **Оптимизация Web UI**: удалён паразитный сброс формы по таймеру, опрос статуса аудита выполняется только при раскрытой карточке, предотвращены утечки памяти.
* **Кэширование API**: добавлен HTTP-заголовок `Cache-Control: no-store` для роута `/dsh-shadow-auditor/audit`.

---

## 📄 Лицензия

MIT © [GooDAnDReaDY](https://github.com/GooDAnDReaDY)
