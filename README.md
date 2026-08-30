# dsh-shadow-auditor

DSH plugin for background security audits, secret leakage detection, and command safety for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness).

## Tools
- `shadow_auditor_scan_diff`
- `shadow_auditor_check_command`
- `shadow_auditor_rules_list`

## Settings
Located in **Settings -> Plugins -> Shadow Security Auditor**:
- `strictSecretScanning`: Block execution if API keys or private tokens detected in diff (default: `true`)
- `blockDangerousCommands`: Block destructive flags like --force, rm -rf /, etc. (default: `true`)
- `enableAuditBadge`: Display security shield badge in approval dialogs (default: `true`)

## Verification
```bash
npm test
```
