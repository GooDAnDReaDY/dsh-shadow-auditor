window.__ModuleLoader__.load({
  id: '@goodandready/dsh-shadow-auditor',
  factory: (require) => {
    var module = { exports: {} };
    const React = require('react');
    const NS = '@goodandready/dsh-shadow-auditor';

    let ChevronIcon = null;
    try {
      const primitives = require('@deepseek-ai/dsh-client-ui-primitives');
      ChevronIcon = primitives && primitives.IconChevronDownOutline14;
    } catch (_) { ChevronIcon = null; }

    function FallbackChevron(props) {
      return React.createElement('svg', { width: 14, height: 14, viewBox: '0 0 14 14', fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, style: props.style },
        React.createElement('path', { d: 'M3.5 5.25L7 8.75L10.5 5.25' })
      );
    }
    const Chevron = ChevronIcon || FallbackChevron;

    function ShieldIcon({ level }) {
      const stroke = level === 'red' ? 'var(--dsw-alias-color-danger, #ef4444)' :
                     level === 'yellow' ? 'var(--dsw-alias-color-warning, #f59e0b)' :
                     'var(--dsw-alias-color-success, #10b981)';
      return React.createElement('svg', { width: 14, height: 14, viewBox: '0 0 24 24', fill: 'none', stroke, strokeWidth: 2, strokeLinecap: 'round', strokeLinejoin: 'round' },
        React.createElement('path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' })
      );
    }

    function ensureCss() {
      if (typeof document === 'undefined') return;
      if (document.getElementById('dsh-shadow-auditor-full-css')) return;
      const style = document.createElement('style');
      style.id = 'dsh-shadow-auditor-full-css';
      style.dataset.dshPlugin = NS;
      style.setAttribute('data-dsh-plugin', NS);
      style.textContent = `
.sa-page { display: flex; flex-direction: column; gap: 16px; padding: 4px 0 24px; max-width: 960px; font-family: inherit; }
.sa-header { display: flex; flex-direction: column; gap: 8px; padding-bottom: 14px; border-bottom: 1px solid var(--dsw-alias-border-l2); }
.sa-page-title { font-size: 20px; font-weight: 700; color: var(--dsw-alias-label-primary); display: flex; align-items: center; gap: 10px; }
.sa-page-sub { font-size: 13px; color: var(--dsw-alias-label-secondary); line-height: 1.5; }

.sa-section-card { border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-3); border-radius: 12px; padding: 16px 18px; display: flex; flex-direction: column; gap: 12px; }
.sa-section-title { font-size: 15px; font-weight: 600; color: var(--dsw-alias-label-primary); display: flex; align-items: center; justify-content: space-between; }
.sa-section-desc { font-size: 13px; color: var(--dsw-alias-label-secondary); margin-top: -4px; line-height: 1.4; }

.sa-row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.sa-grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; }

.sa-badge { font-size: 12px; padding: 3px 10px; border-radius: 999px; border: 1px solid var(--dsw-alias-border-l2); display: inline-flex; align-items: center; gap: 5px; font-weight: 500; }
.sa-badge-ok { border-color: var(--dsw-alias-state-success-primary, #10b981); color: var(--dsw-alias-state-success-primary, #10b981); background: rgba(16,185,129,0.08); }
.sa-badge-warn { border-color: var(--dsw-alias-state-warning-primary, #f59e0b); color: var(--dsw-alias-state-warning-primary, #f59e0b); background: rgba(245,158,11,0.08); }
.sa-badge-bad { border-color: var(--dsw-alias-state-error-primary, #ef4444); color: var(--dsw-alias-state-error-primary, #ef4444); background: rgba(239,68,68,0.08); }

.sa-field { display: flex; flex-direction: column; gap: 4px; }
.sa-field-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.sa-field-label { font-size: 13px; font-weight: 500; color: var(--dsw-alias-label-primary); }
.sa-field-desc { font-size: 12px; color: var(--dsw-alias-label-secondary); line-height: 1.4; }

.sa-input { height: 34px; border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); border-radius: 8px; padding: 0 10px; font-size: 13px; box-sizing: border-box; }
.sa-input:focus { outline: none; border-color: var(--dsw-alias-state-brand-primary); }
.sa-select { height: 34px; border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); border-radius: 8px; padding: 0 10px; font-size: 13px; box-sizing: border-box; cursor: pointer; }

.sa-btn { appearance: none; font: inherit; cursor: pointer; border: 1px solid var(--dsw-alias-border-l2); border-radius: 8px; padding: 7px 14px; font-size: 13px; background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); font-weight: 500; display: inline-flex; align-items: center; justify-content: center; gap: 6px; transition: all .15s ease; }
.sa-btn:hover:not(:disabled) { background: var(--dsw-alias-bg-layer-4, var(--dsw-alias-bg-layer-2)); border-color: var(--dsw-alias-label-dimmed, var(--dsw-alias-border-l2)); }
.sa-btn-primary { background: var(--dsw-alias-label-primary); color: var(--dsw-alias-bg-layer-3); border-color: transparent; }
.sa-btn-primary:hover:not(:disabled) { opacity: 0.9; }
.sa-btn:disabled { opacity: 0.5; cursor: not-allowed; }

.sa-banner-warning { padding: 12px 14px; border-radius: 8px; background: rgba(245,158,11,0.1); border: 1px solid var(--dsw-alias-state-warning-primary, #f59e0b); color: var(--dsw-alias-label-primary); font-size: 13px; }
.sa-foot { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 8px; }
`;
      document.head.appendChild(style);
    }

    function AuditShieldChip({ ctx: _ctx }) {
      const [audit, setAudit] = React.useState({ level: 'green', hits: [], at: 0 });
      const [open, setOpen] = React.useState(false);
      const ref = React.useRef(null);

      const fetchStatus = () => {
        if (typeof document !== 'undefined' && document.hidden) return;
        fetch('/dsh-shadow-auditor/audit', { headers: { accept: 'application/json' } })
          .then(r => r.ok ? r.json() : null)
          .then(j => { if (j && j.level) setAudit(j); })
          .catch(() => {});
      };

      React.useEffect(() => {
        let alive = true;
        fetchStatus();
        const id = setInterval(() => { if (alive) fetchStatus(); }, 4000);
        return () => { alive = false; clearInterval(id); };
      }, []);

      React.useEffect(() => {
        if (!open) return;
        const onDocClick = (e) => {
          if (ref.current && !ref.current.contains(e.target)) setOpen(false);
        };
        document.addEventListener('mousedown', onDocClick);
        return () => document.removeEventListener('mousedown', onDocClick);
      }, [open]);

      const levelLabel = audit.level === 'red' ? 'Shield: Red' : audit.level === 'yellow' ? 'Shield: Yellow' : 'Shield: Safe';
      const badgeColor = audit.level === 'red' ? 'var(--dsw-alias-color-danger, #ef4444)' :
                         audit.level === 'yellow' ? 'var(--dsw-alias-color-warning, #f59e0b)' :
                         'var(--dsw-alias-color-success, #10b981)';

      return React.createElement('div', { ref, className: 'sa-chip-container', style: { position: 'relative', display: 'inline-flex', alignItems: 'center' } },
        React.createElement('button', {
          type: 'button',
          className: 'sa-chip-btn',
          onClick: () => setOpen(!open),
          title: 'Security Auditor Shield',
          style: {
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '3px 8px',
            borderRadius: '6px',
            border: '1px solid var(--dsw-alias-border-l2)',
            background: 'var(--dsw-alias-bg-layer-3)',
            color: 'var(--dsw-alias-label-primary)',
            fontSize: '12px',
            fontWeight: 500,
            cursor: 'pointer'
          }
        },
          React.createElement(ShieldIcon, { level: audit.level }),
          React.createElement('span', { style: { color: badgeColor } }, levelLabel)
        ),
        open && React.createElement('div', {
          className: 'sa-chip-popover',
          style: {
            position: 'absolute',
            top: 'calc(100% + 6px)',
            right: 0,
            zIndex: 1000,
            width: '280px',
            padding: '12px',
            borderRadius: '8px',
            border: '1px solid var(--dsw-alias-border-l2)',
            background: 'var(--dsw-alias-bg-layer-3)',
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
            fontSize: '12px',
            color: 'var(--dsw-alias-label-primary)'
          }
        },
          React.createElement('div', { style: { fontWeight: 600, marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' } },
            React.createElement(ShieldIcon, { level: audit.level }),
            React.createElement('span', null, 'Shadow Security Auditor')
          ),
          React.createElement('div', { style: { color: 'var(--dsw-alias-label-secondary)', marginBottom: '8px' } },
            audit.level === 'green' ? 'No security threats detected in current session.' :
            audit.level === 'yellow' ? 'Warning: suspicious infra or potential secrets detected.' :
            'Alert: destructive commands or secrets blocked by guard!'
          ),
          audit.hits && audit.hits.length > 0 && React.createElement('div', { style: { maxHeight: '100px', overflowY: 'auto' } },
            audit.hits.map((h, idx) => React.createElement('div', { key: idx, style: { fontSize: '11px', color: badgeColor, marginTop: '4px' } },
              '• ' + (h.label || h.type) + ': ' + (h.match || '')
            ))
          ),
          React.createElement('div', { style: { marginTop: '8px', paddingTop: '6px', borderTop: '1px solid var(--dsw-alias-border-l2)', fontSize: '11px', color: 'var(--dsw-alias-label-tertiary)' } },
            'Use chat command /audit for full bill.'
          )
        )
      );
    }

    function SettingsPage({ ctx }) {
      const [snap, setSnap] = React.useState({ status: 'loading', value: null, writable: false });
      const [draft, setDraft] = React.useState({
        strictSecretScanning: true,
        blockDangerousCommands: true,
        enableAuditBadge: true,
        enableAuditLog: true,
        maxFileSizeMb: 50,
        retentionDays: 30,
        diffGateMode: 'warning',
        enableSastScan: true,
        enablePromptInjectionScan: true,
      });
      const [saving, setSaving] = React.useState(false);
      const [msg, setMsg] = React.useState('');
      const [audit, setAudit] = React.useState({ level: 'green', hits: [], at: 0 });

      const initializedRef = React.useRef(false);

      React.useEffect(() => {
        ensureCss();
      }, []);

      React.useEffect(() => {
        let off = null;
        try {
          const scope = ctx.settingsScope && ctx.settingsScope.bind ? ctx.settingsScope.bind({ namespace: NS }) : null;
          if (!scope) { setSnap({ status: 'unavailable', value: null, writable: false }); return; }
          const update = () => {
            const s = scope.getSnapshot ? scope.getSnapshot() : { status: 'unavailable', value: null, writable: false };
            setSnap(s);
            if (s.status === 'ready' && s.value && !initializedRef.current) {
              initializedRef.current = true;
              setDraft({
                strictSecretScanning: s.value.strictSecretScanning ?? true,
                blockDangerousCommands: s.value.blockDangerousCommands ?? true,
                enableAuditBadge: s.value.enableAuditBadge ?? true,
                enableAuditLog: s.value.enableAuditLog ?? true,
                maxFileSizeMb: s.value.maxFileSizeMb ?? 50,
                retentionDays: s.value.retentionDays ?? 30,
                diffGateMode: s.value.diffGateMode ?? 'warning',
                enableSastScan: s.value.enableSastScan ?? true,
                enablePromptInjectionScan: s.value.enablePromptInjectionScan ?? true,
              });
            }
          };
          update();
          if (scope.subscribe) off = scope.subscribe(update);
        } catch (_) { setSnap({ status: 'unavailable', value: null, writable: false }); }
        return () => { try { off && off(); } catch {} };
      }, []);

      React.useEffect(() => {
        let alive = true;
        const fetchAudit = () => {
          if (typeof document !== 'undefined' && document.hidden) return;
          fetch('/dsh-shadow-auditor/audit', { headers: { accept: 'application/json' } })
            .then((r) => r.ok ? r.json() : null)
            .then((j) => { if (alive && j && j.level) setAudit(j); })
            .catch(() => {});
        };
        fetchAudit();
        const iv = setInterval(fetchAudit, 4000);
        return () => { alive = false; clearInterval(iv); };
      }, []);

      const t = (() => { try { return ctx.locale && ctx.locale.bind ? ctx.locale.bind(NS) : (k) => k; } catch (_) { return (k) => k; } })();

      const isReady = snap.status === 'ready';

      const onSave = async () => {
        if (!isReady) return;
        setSaving(true); setMsg('');
        try {
          if (!ctx.settingsScope || !ctx.settingsScope.bind) {
            setMsg(t('unavailable') || 'Settings service unavailable');
            setSaving(false);
            return;
          }
          const scope = ctx.settingsScope.bind({ namespace: NS });
          const errors = [];
          const keys = [
            'strictSecretScanning',
            'blockDangerousCommands',
            'enableAuditBadge',
            'enableAuditLog',
            'maxFileSizeMb',
            'retentionDays',
            'diffGateMode',
            'enableSastScan',
            'enablePromptInjectionScan'
          ];
          for (const key of keys) {
            try {
              if (scope.set) await scope.set(key, draft[key]);
            } catch (err) {
              errors.push(key + ': ' + String(err && err.message || err));
            }
          }
          if (errors.length) setMsg(errors.join('; '));
          else setMsg(t('saved') || 'Saved');
        } catch (e) { setMsg(String(e && e.message || e)); }
        setSaving(false);
      };

      if (snap.status === 'unavailable') {
        return React.createElement('div', { className: 'sa-page' },
          React.createElement('div', { className: 'sa-banner-warning' }, t('unavailable') || 'Settings service is currently unavailable.')
        );
      }

      const shieldBadgeClass = audit.level === 'red' ? 'sa-badge sa-badge-bad' :
                               audit.level === 'yellow' ? 'sa-badge sa-badge-warn' :
                               'sa-badge sa-badge-ok';
      const shieldBadgeText = audit.level === 'red' ? (t('shield.red') || 'Alert') :
                              audit.level === 'yellow' ? (t('shield.yellow') || 'Warning') :
                              (t('shield.green') || 'Secure');

      return React.createElement('div', { className: 'sa-page' },
        // Header
        React.createElement('div', { className: 'sa-header' },
          React.createElement('div', { className: 'sa-page-title' },
            '🛡️ ' + (t('title') || 'Shadow Security Auditor'),
            React.createElement('span', { className: shieldBadgeClass },
              React.createElement(ShieldIcon, { level: audit.level }),
              shieldBadgeText
            )
          ),
          React.createElement('div', { className: 'sa-page-sub' }, t('header.sub') || 'Real-time security auditing, secret leak prevention, destructive command interception, and code diff gating.')
        ),

        // Section 1: Security & Guard Policies
        React.createElement('div', { className: 'sa-section-card' },
          React.createElement('div', { className: 'sa-section-title' }, '🔒 ' + (t('sec.guards_title') || 'Execution Safety & Guards')),
          React.createElement('div', { className: 'sa-section-desc' }, t('sec.guards_desc') || 'Proactive boundary checks intercepting dangerous operations before command execution.'),
          React.createElement('div', { className: 'sa-grid-2' },
            React.createElement('div', { className: 'sa-field' },
              React.createElement('div', { className: 'sa-field-row' },
                React.createElement('span', { className: 'sa-field-label' }, t('strictSecrets') || 'Strict secret scanning'),
                React.createElement('input', {
                  type: 'checkbox',
                  disabled: !isReady || saving,
                  checked: !!draft.strictSecretScanning,
                  onChange: (e) => setDraft({ ...draft, strictSecretScanning: e.target.checked })
                })
              ),
              React.createElement('div', { className: 'sa-field-desc' }, t('strictSecretsDesc') || 'Block on API keys / private tokens in diff')
            ),
            React.createElement('div', { className: 'sa-field' },
              React.createElement('div', { className: 'sa-field-row' },
                React.createElement('span', { className: 'sa-field-label' }, t('blockCommands') || 'Block dangerous commands'),
                React.createElement('input', {
                  type: 'checkbox',
                  disabled: !isReady || saving,
                  checked: !!draft.blockDangerousCommands,
                  onChange: (e) => setDraft({ ...draft, blockDangerousCommands: e.target.checked })
                })
              ),
              React.createElement('div', { className: 'sa-field-desc' }, t('blockCommandsDesc') || 'Checks --force, rm -rf, systemctl, DB drop, curl|bash, exfiltration')
            ),
            React.createElement('div', { className: 'sa-field' },
              React.createElement('div', { className: 'sa-field-row' },
                React.createElement('span', { className: 'sa-field-label' }, t('auditBadge') || 'Audit shield chip'),
                React.createElement('input', {
                  type: 'checkbox',
                  disabled: !isReady || saving,
                  checked: !!draft.enableAuditBadge,
                  onChange: (e) => setDraft({ ...draft, enableAuditBadge: e.target.checked })
                })
              ),
              React.createElement('div', { className: 'sa-field-desc' }, t('auditBadgeDesc') || 'Display security status shield badge in chat session header')
            )
          )
        ),

        // Section 2: Code-Security Diff Gate
        React.createElement('div', { className: 'sa-section-card' },
          React.createElement('div', { className: 'sa-section-title' }, '🔍 ' + (t('sec.diff_gate_title') || 'Code-Security Diff Gate & SAST')),
          React.createElement('div', { className: 'sa-section-desc' }, t('sec.diff_gate_desc') || 'Pre-approval multi-pattern analysis for source modifications, SAST vulnerabilities and prompt injection.'),
          React.createElement('div', { className: 'sa-grid-2' },
            React.createElement('div', { className: 'sa-field' },
              React.createElement('div', { className: 'sa-field-row' },
                React.createElement('span', { className: 'sa-field-label' }, t('diffGateMode') || 'Diff Gate Policy'),
                React.createElement('select', {
                  className: 'sa-select',
                  disabled: !isReady || saving,
                  value: draft.diffGateMode || 'warning',
                  onChange: (e) => setDraft({ ...draft, diffGateMode: e.target.value })
                },
                  React.createElement('option', { value: 'disabled' }, t('diffGate.disabled') || 'Disabled'),
                  React.createElement('option', { value: 'warning' }, t('diffGate.warning') || 'Warning (Audit)'),
                  React.createElement('option', { value: 'block' }, t('diffGate.block') || 'Block (Strict)')
                )
              ),
              React.createElement('div', { className: 'sa-field-desc' }, t('diffGateModeDesc') || 'Diff/approval boundary gate policy: warning or block on high/critical findings')
            ),
            React.createElement('div', { className: 'sa-field' },
              React.createElement('div', { className: 'sa-field-row' },
                React.createElement('span', { className: 'sa-field-label' }, t('enableSast') || 'Insecure code patterns (SAST)'),
                React.createElement('input', {
                  type: 'checkbox',
                  disabled: !isReady || saving,
                  checked: draft.enableSastScan !== false,
                  onChange: (e) => setDraft({ ...draft, enableSastScan: e.target.checked })
                })
              ),
              React.createElement('div', { className: 'sa-field-desc' }, t('enableSastDesc') || 'Inspect diffs for SQLi, command injection, path traversal, and eval()')
            ),
            React.createElement('div', { className: 'sa-field' },
              React.createElement('div', { className: 'sa-field-row' },
                React.createElement('span', { className: 'sa-field-label' }, t('enablePromptInjection') || 'Prompt-injection scanner'),
                React.createElement('input', {
                  type: 'checkbox',
                  disabled: !isReady || saving,
                  checked: draft.enablePromptInjectionScan !== false,
                  onChange: (e) => setDraft({ ...draft, enablePromptInjectionScan: e.target.checked })
                })
              ),
              React.createElement('div', { className: 'sa-field-desc' }, t('enablePromptInjectionDesc') || 'Scan diffs for adversarial system prompt override and jailbreak attempts')
            )
          )
        ),

        // Section 3: Audit Log & Storage
        React.createElement('div', { className: 'sa-section-card' },
          React.createElement('div', { className: 'sa-section-title' }, '📁 ' + (t('sec.audit_log_title') || 'Audit Trail & Storage')),
          React.createElement('div', { className: 'sa-section-desc' }, t('sec.audit_log_desc') || 'Persistent JSONL telemetry log with automated gzip rotation and lifecycle retention.'),
          React.createElement('div', { className: 'sa-grid-2' },
            React.createElement('div', { className: 'sa-field' },
              React.createElement('div', { className: 'sa-field-row' },
                React.createElement('span', { className: 'sa-field-label' }, t('enableAuditLog') || 'Record audit log'),
                React.createElement('input', {
                  type: 'checkbox',
                  disabled: !isReady || saving,
                  checked: !!draft.enableAuditLog,
                  onChange: (e) => setDraft({ ...draft, enableAuditLog: e.target.checked })
                })
              ),
              React.createElement('div', { className: 'sa-field-desc' }, t('enableAuditLogDesc') || 'Maintain persistent JSONL audit trail with automated rotation')
            ),
            React.createElement('div', { className: 'sa-field' },
              React.createElement('div', { className: 'sa-field-row' },
                React.createElement('span', { className: 'sa-field-label' }, t('maxFileSizeMb') || 'Max log file size (MB)'),
                React.createElement('input', {
                  className: 'sa-input',
                  type: 'number',
                  min: 1,
                  max: 1000,
                  style: { width: '90px' },
                  disabled: !isReady || saving,
                  value: Number(draft.maxFileSizeMb) || 50,
                  onChange: (e) => setDraft({ ...draft, maxFileSizeMb: Math.max(1, Number(e.target.value) || 50) })
                })
              ),
              React.createElement('div', { className: 'sa-field-desc' }, t('maxFileSizeMbDesc') || 'Compress log to gzip archive when size exceeds this limit')
            ),
            React.createElement('div', { className: 'sa-field' },
              React.createElement('div', { className: 'sa-field-row' },
                React.createElement('span', { className: 'sa-field-label' }, t('retentionDays') || 'Log retention (days)'),
                React.createElement('input', {
                  className: 'sa-input',
                  type: 'number',
                  min: 1,
                  max: 365,
                  style: { width: '90px' },
                  disabled: !isReady || saving,
                  value: Number(draft.retentionDays) || 30,
                  onChange: (e) => setDraft({ ...draft, retentionDays: Math.max(1, Number(e.target.value) || 30) })
                })
              ),
              React.createElement('div', { className: 'sa-field-desc' }, t('retentionDaysDesc') || 'Automatically remove gzip archives older than this threshold')
            )
          )
        ),

        // Section 4: Live Telemetry & Diagnostics
        audit.hits && audit.hits.length ? React.createElement('div', { className: 'sa-section-card' },
          React.createElement('div', { className: 'sa-section-title' },
            '📊 ' + (t('lastAudit') || 'Last Audit Hits'),
            React.createElement('span', { className: shieldBadgeClass }, audit.level)
          ),
          React.createElement('div', { style: { fontSize: '12px', color: 'var(--dsw-alias-label-secondary)' } },
            (audit.source ? `Source: ${audit.source} · ` : '') + (audit.at ? new Date(audit.at).toLocaleTimeString() : '')
          ),
          React.createElement('ul', { style: { margin: '4px 0 0 16px', padding: 0, fontSize: '12px' } },
            audit.hits.slice(0, 5).map((h, i) => React.createElement('li', { key: i, style: { marginBottom: '3px' } },
              React.createElement('strong', null, (h.label || h.type || h.id) + ': '),
              String(h.match || '').slice(0, 80)
            ))
          )
        ) : null,

        // Footer Actions
        React.createElement('div', { className: 'sa-foot' },
          msg ? React.createElement('span', { style: { fontSize: '13px', color: 'var(--dsw-alias-label-secondary)' } }, msg) : React.createElement('span', null),
          React.createElement('button', {
            type: 'button',
            className: 'sa-btn sa-btn-primary',
            onClick: onSave,
            disabled: !isReady || saving
          }, saving ? (t('saving') || 'Saving…') : (t('save') || 'Save Changes'))
        )
      );
    }

    function PluginCard(props) {
      const [open, setOpen] = React.useState(false);
      const ctx = props.ctx;
      const t = (() => { try { return ctx.locale && ctx.locale.bind ? ctx.locale.bind(NS) : (k) => k; } catch (_) { return (k) => k; } })();

      React.useEffect(() => {
        ensureCss();
      }, []);

      return React.createElement('li', { className: 'sa-section-card', style: { listStyle: 'none', marginBottom: '12px' } },
        React.createElement('button', {
          type: 'button',
          style: {
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            width: '100%',
            padding: 0,
            textAlign: 'left'
          },
          'aria-expanded': open,
          onClick: () => setOpen(!open)
        },
          React.createElement('div', { style: { flex: 1 } },
            React.createElement('div', { style: { fontWeight: 600, fontSize: '15px', color: 'var(--dsw-alias-label-primary)' } }, t('title') || 'Shadow Security Auditor'),
            React.createElement('div', { style: { fontSize: '13px', color: 'var(--dsw-alias-label-secondary)' } }, t('subtitle') || 'Secrets & command safety')
          ),
          React.createElement('span', { style: { transform: open ? 'rotate(180deg)' : 'none', transition: 'transform .16s', color: 'var(--dsw-alias-label-secondary)' } },
            React.createElement(Chevron)
          )
        ),
        open ? React.createElement('div', { style: { marginTop: '16px' } },
          React.createElement(SettingsPage, { ...props, ctx })
        ) : null
      );
    }

    module.exports.inject = ['slots', 'locale', 'settingsScope'];
    module.exports.apply = function apply(ctx) {
      try {
        ctx.locale.register(NS, {
          en: {
            title: 'Shadow Security Auditor',
            subtitle: 'Secrets, dangerous command prevention & code diff gate',
            'header.sub': 'Real-time security auditing, secret leak prevention, destructive command interception, and code diff gating.',
            'sec.guards_title': 'Execution Safety & Guards',
            'sec.guards_desc': 'Proactive boundary checks intercepting dangerous operations before command execution.',
            'sec.diff_gate_title': 'Code-Security Diff Gate & SAST',
            'sec.diff_gate_desc': 'Pre-approval multi-pattern analysis for source modifications, SAST vulnerabilities and prompt injection.',
            'sec.audit_log_title': 'Audit Trail & Storage',
            'sec.audit_log_desc': 'Persistent JSONL telemetry log with automated gzip rotation and lifecycle retention.',
            saved: 'Settings saved',
            strictSecrets: 'Strict secret scanning',
            strictSecretsDesc: 'Block execution if API keys or private tokens detected in diff',
            blockCommands: 'Block dangerous commands',
            blockCommandsDesc: 'Checks --force, rm -rf, systemctl, DB drop, curl|bash, exfiltration',
            auditBadge: 'Audit shield chip',
            auditBadgeDesc: 'Display security status shield badge in chat session header',
            diffGateMode: 'Diff Gate Policy',
            diffGateModeDesc: 'Diff/approval boundary gate policy: warning or block on high/critical findings',
            'diffGate.disabled': 'Disabled',
            'diffGate.warning': 'Warning (Audit)',
            'diffGate.block': 'Block (Strict)',
            enableSast: 'Insecure code patterns (SAST)',
            enableSastDesc: 'Inspect diffs for SQLi, command injection, path traversal, and eval()',
            enablePromptInjection: 'Prompt-injection scanner',
            enablePromptInjectionDesc: 'Scan diffs for adversarial system prompt override and jailbreak attempts',
            enableAuditLog: 'Record audit log',
            enableAuditLogDesc: 'Maintain persistent JSONL audit trail with automated rotation',
            maxFileSizeMb: 'Max log file size (MB)',
            maxFileSizeMbDesc: 'Compress log to gzip archive when size exceeds this limit',
            retentionDays: 'Log retention (days)',
            retentionDaysDesc: 'Automatically remove gzip archives older than this threshold',
            loading: 'Loading…',
            unavailable: 'Settings service is currently unavailable (read-only mode).',
            save: 'Save Changes',
            saving: 'Saving…',
            lastAudit: 'Last audit',
            'shield.green': 'Safe',
            'shield.yellow': 'Warning',
            'shield.red': 'Alert',
          },
          ru: {
            title: 'Теневой аудитор безопасности',
            subtitle: 'Защита от утечек секретов, опасных команд и шлюз диффов',
            'header.sub': 'Аудит безопасности в реальном времени, предотвращение утечек секретов, перехват опасных команд и инспекция кода.',
            'sec.guards_title': 'Безопасность выполнения и гарды',
            'sec.guards_desc': 'Упреждающие проверки команд перед их непосредственным запуском.',
            'sec.diff_gate_title': 'Шлюз безопасности кода (Diff Gate) и SAST',
            'sec.diff_gate_desc': 'Анализ диффов перед утверждением: уязвимости кода, утечки ключей и prompt injection.',
            'sec.audit_log_title': 'Журнал аудита и хранение',
            'sec.audit_log_desc': 'Персистентный JSONL-журнал с автоматической gzip-ротацией и очисткой по сроку давности.',
            saved: 'Настройки сохранены',
            strictSecrets: 'Строгое сканирование секретов',
            strictSecretsDesc: 'Блокировать фиксацию API-ключей и токенов в дифах',
            blockCommands: 'Блокировать опасные команды',
            blockCommandsDesc: 'Перехват --force, rm -rf, systemctl, DROP DB, curl|bash, эксфильтрации',
            auditBadge: 'Бейдж щита аудита',
            auditBadgeDesc: 'Отображать интерактивный чип безопасности в шапке чата',
            diffGateMode: 'Политика Diff Gate',
            diffGateModeDesc: 'Поведение шлюза безопасности: предупреждение в аудит или строгая блокировка',
            'diffGate.disabled': 'Отключен',
            'diffGate.warning': 'Предупреждение (Аудит)',
            'diffGate.block': 'Блокировка (Строгий)',
            enableSast: 'Поиск уязвимостей в коде (SAST)',
            enableSastDesc: 'Поиск SQL-инъекций, внедрения команд, path traversal и eval()',
            enablePromptInjection: 'Сканер prompt-инъекций',
            enablePromptInjectionDesc: 'Поиск попыток перезаписи системного промпта и jailbreak',
            enableAuditLog: 'Запись журнала аудита',
            enableAuditLogDesc: 'Вести персистентный JSONL-журнал с автоматической ротацией',
            maxFileSizeMb: 'Макс. размер файла лога (МБ)',
            maxFileSizeMbDesc: 'Архивировать в gzip при превышении данного размера',
            retentionDays: 'Хранение логов (дней)',
            retentionDaysDesc: 'Автоматически удалять gzip-архивы старше заданного срока',
            loading: 'Загрузка…',
            unavailable: 'Сервис настроек недоступен (режим только для чтения).',
            save: 'Сохранить изменения',
            saving: 'Сохранение…',
            lastAudit: 'Последний аудит',
            'shield.green': 'Безопасно',
            'shield.yellow': 'Внимание',
            'shield.red': 'Опасность',
          }
        });
      } catch (_) {}

      try {
        if (ctx.slots && typeof ctx.slots.inject === 'function') {
          ctx.slots.inject('settings.plugin.item', () =>
            ctx.slots.register(
              { name: 'settings.plugin.item', key: NS, locale: NS, inject: () => ({ ctx }) },
              PluginCard,
            )
          );
          ctx.slots.inject('conversation.session.header.utilities', () =>
            ctx.slots.register(
              { name: 'conversation.session.header.utilities', id: 'dsh-shadow-auditor-chip', order: 5, inject: () => ({ ctx }) },
              AuditShieldChip,
            )
          );
        }
      } catch (_) {}
    };
    return module.exports;
  }
});
