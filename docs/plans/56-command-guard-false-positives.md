# План: ложные срабатывания dsh-shadow-auditor

- Issue: Gitea goodandready/dsh-shadow-auditor#56; conformance-матрица согласована с dsh-approval-gate#16.
- Цель: разрешать rm -f без рекурсивного флага, проверять защищённые записи по отдельным командам и этапам pipeline, сохранять реальные блокировки.
- Другие issues репозитория в эту ветку не входят; пакет не публикуется.
- Base: origin/main 1d1233c4b4d715f9ec840db88b40ed02ffc9265c.
- Ветка/worktree: fix/shadow-auditor-command-false-positives.

## Этапы

1. [x] Изучить open issues и связанные #56/#16, guards, тесты, дизайн-контракт.
2. [x] Обновить #56 и подготовить worktree.
3. [x] Разделять команды и pipeline stages с учётом кавычек и экранирования.
4. [x] Требовать рекурсивный флаг r для блокировки rm; одиночный f разрешён.
5. [x] Добавить регрессии на ложные срабатывания и настоящие блокировки, включая tee и редиректы.
6. [x] Синхронизировать EN/ZH/RU документацию и DESIGN; внутренние файлы остаются вне npm allowlist.
7. [x] Прогнать полный npm test, package preflight и npm pack.
8. [x] Установить и проверить кандидат на изолированном MiniPC профиле, удалить кандидат и архив; профиль снова healthy / DSH_TEST_OK.
9. [ ] Commit/push и PR. Не выполнять merge/deploy/release без отдельного разрешения.

## Результат проверок

- npm test: 33 pass, 0 fail, 2 skip из-за отсутствующей peer dependency @deepseek-ai/schemastery в standalone unit-test окружении.
- diff --check чист; npm pack: 19 файлов, 54109 байт; внутренних AGENTS.md/index.md/docs/plans в архиве нет.
- Preflight: FAIL=1 из-за 19 пустых catch в baseline-файлах lib/recorder.js и lib/index.js, без изменений в этой задаче; WARN=3 по существующим цветам, отсутствию req.method и размеру lib/client.js. Остальные проверки прошли.
