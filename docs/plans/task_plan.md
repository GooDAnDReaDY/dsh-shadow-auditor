# Task Plan: Stability Refinements (#41) (v0.2.7)

## Overview
Eliminate false positives, fix /audit slash command OOM, and optimize polling in `@goodandready/dsh-shadow-auditor`.

## Phases
- [ ] Phase 1: Command Guard Precision (`lib/guards/command.js`)
- [ ] Phase 2: SAST Comments and Path Traversal Whitelisting (`lib/diff-gate/sast.js`)
- [ ] Phase 3: Test and Doc File Awareness (`lib/diff-gate/gate.js`)
- [ ] Phase 4: /audit Slash Command OOM Fix (`lib/index.js`)
- [ ] Phase 5: Client Tab Visibility Optimization & Error Logging (`lib/client.js`, `lib/recorder.js`)
- [ ] Phase 6: Unit Test Coverage for Edge Cases (`test/stability-027.test.mjs`)
- [ ] Phase 7: Docs, Version Bump to 0.2.7, Packaging
- [ ] Phase 8: Verification (Test Server MiniPC & Production RC MiniAI)
