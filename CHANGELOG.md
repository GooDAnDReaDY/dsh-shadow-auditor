# Changelog

All notable changes to `@goodandready/dsh-shadow-auditor` are documented in this file.

## [0.2.15] - 2026-09-24

### Added
- **Destructive Deletion Workspace Guard (#103)**: Strictly block recursive deletions (`rm -rf`, PowerShell `Remove-Item -Recurse`, `rd /s`, `git clean -fdx`) targeting filesystem root (`/`, `~`, `.`) or paths resolving outside the session workspace.
- **Critical System Prefix Protection (#105)**: Unconditional protection for sensitive system directories (`~/.dsh`, `~/.claude`, `~/.ssh`, `/etc`, `/usr`, `C:\Windows`), preventing deletion even when the session workspace is located in the home directory.
- **Dry-Run Pass-Through Verification (#104)**: Recognize verification and preview flags (`-WhatIf`, `-Confirm`, `--dry-run`, `git clean -n`), allowing safe preview commands without triggering false-positive deletion blocks, while recording safety audits.

### Fixed
- **Diff Gate Unified Detection Heuristic (#65)**: Fixed false-positive `isUnifiedDiff` heuristic that misclassified regular files containing `@@` markers as diffs and bypassed security scans in `scanFileContent`.

### Performance
- **Diff Gate Large File Scan Optimization (#66)**: Hoisted diff heuristic outside the per-line loop in `scanDiff`, eliminating $O(N \cdot M)$ string operations and reducing 5000+ line diff scan latency from quadratic freeze to ~20ms.

## 0.2.14

### Fixed
- The settings card no longer waits for the removed `settingsScope` service. It uses `configForms` on current DeepSeek Harness (#74).

## [0.2.13] - 2026-09-19

### Fixed
- **Settings reachable again on the plugin's own page**: the current DSH core
  (0.1.6-alpha.2) renders a plugin's configuration page only for entries registered
  in the plugin-list seat `plugins.item`. The view-aware card is now registered there
  (`id: 'dsh-shadow-auditor'`, order 60, static label); the row seat and the legacy
  `settings.plugin.item` card stay as fallbacks.

## [0.2.12] - 2026-09-19

### Fixed
- **Settings reachable again**: the card registered into `settings.plugin.item`, a
  slot the current DSH core (0.1.6-alpha.2) no longer renders, so the plugin's
  settings were unreachable. The surface now registers into the Plugins page row
  seat `plugins.row.config`, keyed
  `@goodandready/dsh-shadow-auditor#dsh-shadow-auditor`
  (`rowConfigKey(package, rowId)`): the plugin's row gains a configure control whose
  page is the settings form (`view: 'page'`, without our card chrome and header —
  the host page draws the title, icon, crumb and padding) plus a one-line state for
  `view: 'summary'`. The legacy seat stays registered as a fallback for older cores.

### Added
- Guard `test/row-seat.test.mjs`: the row key is checked against `package.json` and
  the row id in `cordis.patch.yml`, the seat order must put the row seat first, and
  the page view must drop the card chrome.
