# Plan: Stability, Quality and De-overengineering Overhaul (v0.2.5)

## Summary
Refactor @goodandready/dsh-shadow-auditor to address 10 critical stability, quality, and overengineering issues:
1. Simplify score.js: Eliminate complex 200-event cumulative scoring, window metrics, and math penalties; replace with clean risk classification (low/medium/high / green/yellow/red).
2. Optimize recorder.js: Remove OOM-prone whole-history .gz decompression on /audit, support reading only active/recent records with tail limit.
3. Remove shadow_auditor_rules_list LLM tool: Prevent unnecessary context pollution.
4. Fix memory leak in recentEvents and turnEnds: Subscribe to session disposal/destroy lifecycle and/or use an LRU eviction strategy.
5. Robust error handling in recorder.js: Capture file write errors and emit warnings to ctx.logger.
6. Refine false-positive command regexes in command.js: Avoid blocking benign tools like grep kill or safe commands.
7. Refine false-positive secret regexes in secrets.js: Ensure valid tokens only (proper prefixes/lengths, avoid code tokens).
8. Real UI Security Shield Badge: Register conversation.session.header.utilities slot component in lib/client.js that polls /dsh-shadow-auditor/audit and displays current shield status (green/yellow/red) with details popover.
9. Add default limit (tail 50) for /audit slash command.
10. Proper logging: Replace silent catch (_) {} with ctx.logger.warn/debug where appropriate.

## Phases
- [ ] Phase 1: Planning and Design Contract update
- [x] Phase 2: Core Guards & Score & Recorder refactoring
- [ ] Phase 3: Lifecycle, slash command & memory leak fixes in lib/index.js
- [ ] Phase 4: UI Shield Badge implementation in lib/client.js
- [ ] Phase 5: Test updates and validation
- [ ] Phase 6: Release cycle (PR, test server, production candidate, publication)
EOF

cat << \EOF\ > /mnt/external/Project/DEV/dhsplugins/dsh-shadow-auditor/.worktrees/fix-stability-overhaul-0.2.5/docs/plans/progress.md
# Progress Log: Issue #37 Stability Overhaul

## Session Start: 2026-09-08
- Created Gitea Issue #37
- Created isolated worktree .worktrees/fix-stability-overhaul-0.2.5
- Initialized task_plan.md and findings.md
EOF

cat << \EOF\ > /mnt/external/Project/DEV/dhsplugins/dsh-shadow-auditor/.worktrees/fix-stability-overhaul-0.2.5/docs/plans/findings.md
# Findings & Architecture Decisions

1. Slots in DSH:
- conversation.session.header.utilities is the canonical top header slot for live status chips/badges (as used by dsh-context-lens, dsh-cost-meter, dsh-key-rotation).
- settings.plugin.item is the canonical slot for settings cards.

2. Recorder & OOM:
- Currently AuditRecorder.readAll() unpacks all .gz archives found in shadow-auditor dir.
- For chat /audit, reading only the active uncompressed month .jsonl (with optional limit) is safe and fast.
EOF
