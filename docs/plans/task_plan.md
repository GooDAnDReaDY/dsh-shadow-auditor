# Task Plan: Code-Security Diff Gate (#39) (v0.2.6)

## Overview
Extend `@goodandready/dsh-shadow-auditor` into a code-security diff gate on diff/approval boundaries.

## Phases
- [x] Phase 1: Security Finding & Rule Schema (`lib/diff-gate/schema.js`)
- [x] Phase 2: Enhanced Secret Scanner with Shannon Entropy (`lib/diff-gate/secrets.js`)
- [x] Phase 3: Lightweight SAST Rules (SQLi, Shell, Path, Hardcoded Secrets) (`lib/diff-gate/sast.js`)
- [x] Phase 4: Prompt-Injection Heuristic Scanner (`lib/diff-gate/prompt-injection.js`)
- [x] Phase 5: Diff Gate Orchestration, Warning/Block Policy & Suppression (`lib/diff-gate/gate.js`)
- [x] Phase 6: Core Plugin Integration & Audit Trail (`lib/index.js`, `lib/recorder.js`)
- [x] Phase 7: UI Settings & Header Shield Extension (`lib/client.js`)
- [x] Phase 8: Unit Testing & Synthetic Fixtures (`test/diff-gate.test.mjs`)
- [x] Phase 9: Design Contract & Multilingual Documentation
- [ ] Phase 10: Test Server (MiniPC) & Production Verification, Release Gate
