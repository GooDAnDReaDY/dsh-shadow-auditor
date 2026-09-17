# dsh-shadow-auditor

Host plugin `@goodandready/dsh-shadow-auditor` performs background security auditing and command risk detection.

- DEV: `/mnt/external/Project/DEV/dhsplugins/dsh-shadow-auditor`
- Production deployment uses the immutable package in a DSH profile; no OPT checkout applies.
- Host entry point: `lib/index.js`; command classifier: `lib/guards/command.js`; client UI: `lib/client.js`.
- Design contract: `docs/design/DESIGN.md`.
- Test command: `npm test`.
- Package contents are governed by the explicit allowlist in `package.json`; internal workflow files must not be published.
- Do not change `dsh-lanmode` or unrelated plugin/profile configuration.
