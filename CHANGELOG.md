# Changelog

All notable changes to `@goodandready/dsh-shadow-auditor` are documented in this file.

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
