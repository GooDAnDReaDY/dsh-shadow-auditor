# AGENTS.md for dsh-shadow-auditor

## Project Scope
- Plugin: `@goodandready-private/dsh-shadow-auditor`
- Architecture: DeepSeek Harness Cordis plugin + Web client
- Canonical path: `/mnt/external/Project/DEV/dhsplugins/dsh-shadow-auditor`

## Rules
- Tests must pass: `node --test test/*.test.mjs`
- Settings registered only via `settings.plugin.item` card format.
- No infrastructure paths or credentials hardcoded.
