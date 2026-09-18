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

    function ShieldIcon({ level, size = 14 }) {
      const stroke = level === 'red' ? 'var(--dsw-alias-state-error-primary)' :
                     level === 'yellow' ? 'var(--dsw-alias-state-warning-primary)' :
                     'var(--dsw-alias-state-success-primary)';
      return React.createElement('svg', { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke, strokeWidth: 2, strokeLinecap: 'round', strokeLinejoin: 'round' },
        React.createElement('path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' }),
        React.createElement('path', { d: 'M9 12l2 2 4-4' })
      );
    }

    function RefreshIcon({ size = 13 }) {
      return React.createElement('svg', { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 2, strokeLinecap: 'round', strokeLinejoin: 'round' },
        React.createElement('polyline', { points: '23 4 23 10 17 10' }),
        React.createElement('path', { d: 'M20.49 15a9 9 0 1 1-2.12-9.36L23 10' })
      );
    }

    function ExportIcon({ size = 13 }) {
      return React.createElement('svg', { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 2, strokeLinecap: 'round', strokeLinejoin: 'round' },
        React.createElement('path', { d: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4' }),
        React.createElement('polyline', { points: '7 10 12 15 17 10' }),
        React.createElement('line', { x1: '12', y1: '15', x2: '12', y2: '3' })
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
.sa-badge-ok { border-color: var(--dsw-alias-state-success-primary); color: var(--dsw-alias-state-success-primary); background: color-mix(in srgb, var(--dsw-alias-state-success-primary) 8%, transparent); }
.sa-badge-warn { border-color: var(--dsw-alias-state-warning-primary); color: var(--dsw-alias-state-warning-primary); background: color-mix(in srgb, var(--dsw-alias-state-warning-primary) 8%, transparent); }
.sa-badge-bad { border-color: var(--dsw-alias-state-error-primary); color: var(--dsw-alias-state-error-primary); background: color-mix(in srgb, var(--dsw-alias-state-error-primary) 8%, transparent); }

.sa-field { display: flex; flex-direction: column; gap: 4px; }
.sa-field-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.sa-field-label { font-size: 13px; font-weight: 500; color: var(--dsw-alias-label-primary); }
.sa-field-desc { font-size: 12px; color: var(--dsw-alias-label-secondary); line-height: 1.4; }

.sa-input { height: 34px; border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); border-radius: 8px; padding: 0 10px; font-size: 13px; box-sizing: border-box; }
.sa-input:focus { outline: none; border-color: var(--dsw-alias-state-brand-primary); }
.sa-textarea { border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); border-radius: 8px; padding: 8px 10px; font-size: 12px; font-family: monospace; box-sizing: border-box; resize: vertical; width: 100%; }
.sa-textarea:focus { outline: none; border-color: var(--dsw-alias-state-brand-primary); }
.sa-select { height: 34px; border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); border-radius: 8px; padding: 0 10px; font-size: 13px; box-sizing: border-box; cursor: pointer; }

.sa-btn { appearance: none; font: inherit; cursor: pointer; border: 1px solid var(--dsw-alias-border-l2); border-radius: 8px; padding: 7px 14px; font-size: 13px; background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); font-weight: 500; display: inline-flex; align-items: center; justify-content: center; gap: 6px; transition: all .15s ease; }
.sa-btn:hover:not(:disabled) { background: var(--dsw-alias-bg-layer-4, var(--dsw-alias-bg-layer-2)); border-color: var(--dsw-alias-label-dimmed, var(--dsw-alias-border-l2)); }
.sa-btn-primary { background: var(--dsw-alias-label-primary); color: var(--dsw-alias-bg-layer-3); border-color: transparent; }
.sa-btn-primary:hover:not(:disabled) { opacity: 0.9; }
.sa-btn:disabled { opacity: 0.5; cursor: not-allowed; }

.sa-banner-warning { padding: 12px 14px; border-radius: 8px; background: color-mix(in srgb, var(--dsw-alias-state-warning-primary) 10%, transparent); border: 1px solid var(--dsw-alias-state-warning-primary); color: var(--dsw-alias-label-primary); font-size: 13px; }
.sa-foot { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 8px; }

.sa-feed-item { background: var(--dsw-alias-bg-layer-2); border: 1px solid var(--dsw-alias-border-l2); border-radius: 8px; padding: 10px 12px; cursor: pointer; transition: background .15s ease; }
.sa-feed-item:hover { background: var(--dsw-alias-bg-layer-4, var(--dsw-alias-bg-layer-2)); }
.sa-filter-pill { padding: 4px 10px; border-radius: 999px; font-size: 11px; border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-secondary); cursor: pointer; transition: all .15s ease; }
.sa-filter-pill.active { background: var(--dsw-alias-label-primary); color: var(--dsw-alias-bg-layer-3); border-color: transparent; font-weight: 600; }
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
      const badgeColor = audit.level === 'red' ? 'var(--dsw-alias-state-error-primary)' :
                         audit.level === 'yellow' ? 'var(--dsw-alias-state-warning-primary)' :
                         'var(--dsw-alias-state-success-primary)';

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
            boxShadow: 'var(--dsw-alias-shadow-l2, 0 4px 12px color-mix(in srgb, var(--dsw-alias-label-primary) 15%, transparent))',
            fontSize: '12px',
            color: 'var(--dsw-alias-label-primary)'
          }
        },
          React.createElement('div', { style: { fontWeight: 600, marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' } },
            React.createElement(ShieldIcon, { level: audit.level }),
            React.createElement('span', null, 'Shadow Security Auditor')
          ),
          React.createElement('div', { style: { color: 'var(--dsw-alias-label-secondary)', marginBottom: '8px' } },
            audit.level === 'red' ? 'Alert: destructive commands or secrets blocked by guard!' :
            audit.level === 'yellow' ? 'Warning: suspicious infra or potential secrets detected.' :
            'No security threats detected in current session.'
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
        shellGuardMode: 'enforce',
        enableSastScan: true,
        enablePromptInjectionScan: true,
        customBlockedCommands: '',
        sensitivePathPatterns: '',
      });
      const [saving, setSaving] = React.useState(false);
      const [msg, setMsg] = React.useState('');
      const [audit, setAudit] = React.useState({ level: 'green', hits: [], at: 0 });
      const [events, setEvents] = React.useState([]);
      const [eventsFilter, setEventsFilter] = React.useState('all');
      const [eventsLoading, setEventsLoading] = React.useState(false);
      const [expandedEvent, setExpandedEvent] = React.useState(null);

      const [updateState, setUpdateState] = React.useState({
        currentVersion: '0.2.11',
        latestVersion: '',
        checking: false,
        updating: false,
        updateAvailable: false,
        canAutoUpdate: true,
        notice: '',
        error: '',
      });

      const checkUpdate = React.useCallback(async () => {
        setUpdateState((s) => ({ ...s, checking: true, error: '' }));
        try {
          const res = await fetch('/dsh-shadow-auditor/update');
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const data = await res.json().catch(() => ({}));
          setUpdateState((s) => ({
            ...s,
            checking: false,
            currentVersion: data.currentVersion || s.currentVersion,
            latestVersion: data.latestVersion || '',
            updateAvailable: !!data.updateAvailable,
            canAutoUpdate: data.canAutoUpdate !== false,
          }));
        } catch (_) {
          setUpdateState((s) => ({ ...s, checking: false }));
        }
      }, []);

      React.useEffect(() => {
        checkUpdate();
      }, [checkUpdate]);

      const handleTriggerUpdate = async () => {
        if (updateState.updating) return;
        setUpdateState((s) => ({ ...s, updating: true, error: '', notice: '' }));
        try {
          const res = await fetch('/dsh-shadow-auditor/update', {
            method: 'POST',
            headers: { 'x-dsh-plugin-update': '1' },
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok || data.ok === false || data.error) {
            throw new Error(data.error || `HTTP ${res.status}`);
          }
          const newVer = data.updatedVersion || updateState.latestVersion || updateState.currentVersion;
          setUpdateState((s) => ({
            ...s,
            updating: false,
            updateAvailable: false,
            currentVersion: newVer,
            notice: t('update.done', { version: newVer }),
          }));
          checkUpdate();
        } catch (err) {
          setUpdateState((s) => ({
            ...s,
            updating: false,
            error: t('update.failed', { error: String(err.message || err) }),
          }));
        }
      };

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
                shellGuardMode: s.value.shellGuardMode ?? 'enforce',
                enableSastScan: s.value.enableSastScan ?? true,
                enablePromptInjectionScan: s.value.enablePromptInjectionScan ?? true,
                customBlockedCommands: s.value.customBlockedCommands ?? '',
                sensitivePathPatterns: s.value.sensitivePathPatterns ?? '',
              });
            }
          };
          update();
          if (scope.subscribe) off = scope.subscribe(update);
        } catch (err) {
          ctx.logger?.debug?.('[shadow-auditor] Settings scope initialization failed (error type: ' + (err?.name || 'Error') + ').');
          setSnap({ status: 'unavailable', value: null, writable: false });
        }
        return () => { try { off && off(); } catch (err) { ctx.logger?.debug?.('[shadow-auditor] Settings subscription cleanup failed (error type: ' + (err?.name || 'Error') + ').'); } };
      }, []);

      const fetchAudit = React.useCallback(() => {
        if (typeof document !== 'undefined' && document.hidden) return;
        fetch('/dsh-shadow-auditor/audit', { headers: { accept: 'application/json' } })
          .then((r) => r.ok ? r.json() : null)
          .then((j) => { if (j && j.level) setAudit(j); })
          .catch(() => {});
      }, []);

      const fetchEvents = React.useCallback((filter = 'all') => {
        setEventsLoading(true);
        fetch('/dsh-shadow-auditor/events?limit=30&filter=' + encodeURIComponent(filter), { headers: { accept: 'application/json' } })
          .then(r => r.ok ? r.json() : null)
          .then(j => { if (j && Array.isArray(j.records)) setEvents(j.records); })
          .catch(() => {})
          .finally(() => setEventsLoading(false));
      }, []);

      React.useEffect(() => {
        let alive = true;
        fetchAudit();
        fetchEvents(eventsFilter);
        const iv = setInterval(() => {
          if (alive) {
            fetchAudit();
          }
        }, 5000);
        return () => { alive = false; clearInterval(iv); };
      }, [fetchAudit, fetchEvents, eventsFilter]);

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
            'shellGuardMode',
            'enableSastScan',
            'enablePromptInjectionScan',
            'customBlockedCommands',
            'sensitivePathPatterns'
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

      const onExport = (format) => {
        if (typeof window !== 'undefined') {
          window.open('/dsh-shadow-auditor/export?format=' + encodeURIComponent(format), '_blank');
        }
      };

      if (snap.status === 'unavailable') {
        return React.createElement('div', { className: 'sa-page' },
          React.createElement('div', { className: 'sa-banner-warning' }, t('unavailable') || 'Settings service is currently unavailable.')
        );
      }

      const shieldBadgeClass = audit.level === 'red' ? 'sa-badge sa-badge-bad' :
                               audit.level === 'yellow' ? 'sa-badge sa-badge-warn' :
                               'sa-badge sa-badge-ok';

      const diffFindings = (audit.diffGate && audit.diffGate.findings) || (audit.hits && audit.hits.filter(h => h.remediation || h.explanation)) || [];
      const topFinding = diffFindings.length > 0 ? diffFindings[0] : null;

      return React.createElement('div', { className: 'sa-page' },
        // Header
        React.createElement('div', { className: 'sa-header' },
          React.createElement('div', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' } },
            React.createElement('div', { className: 'sa-page-title' },
              React.createElement(ShieldIcon, { level: audit.level, size: 22 }),
              t('title') || 'Shadow Security Auditor',
              React.createElement('span', { className: shieldBadgeClass }, audit.level)
            ),
            React.createElement('div', { style: { display: 'flex', gap: '8px' } },
              React.createElement('button', {
                type: 'button',
                className: 'sa-btn',
                onClick: () => onExport('json'),
                title: t('action.export_json') || 'Export JSON'
              }, React.createElement(ExportIcon, { size: 12 }), t('action.export_json') || 'Export JSON'),
              React.createElement('button', {
                type: 'button',
                className: 'sa-btn',
                onClick: () => onExport('markdown'),
                title: t('action.export_bill') || 'Export Bill (MD)'
              }, React.createElement(ExportIcon, { size: 12 }), t('action.export_bill') || 'Export Bill (MD)')
            )
          ),
          React.createElement('div', { className: 'sa-page-sub' },
            t('header.sub') || 'Real-time security auditing, secret leak prevention, destructive command interception, and code diff gating.'
          )
        ),

        // Section 1: Execution Safety & Guards
        React.createElement('div', { className: 'sa-section-card' },
          React.createElement('div', { className: 'sa-section-title' },
            '🛡️ ' + (t('sec.guards_title') || 'Execution Safety & Guards')
          ),
          React.createElement('div', { className: 'sa-section-desc' },
            t('sec.guards_desc') || 'Proactive boundary checks intercepting dangerous operations before command execution.'
          ),
          React.createElement('div', { className: 'sa-grid-2' },
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
                React.createElement('span', { className: 'sa-field-label' }, t('shellGuardMode') || 'Shell Guard Policy'),
                React.createElement('select', {
                  className: 'sa-select',
                  disabled: !isReady || saving,
                  value: draft.shellGuardMode || 'enforce',
                  onChange: (e) => setDraft({ ...draft, shellGuardMode: e.target.value })
                },
                  React.createElement('option', { value: 'enforce' }, t('shellGuard.enforce') || 'Enforce (Block execution)'),
                  React.createElement('option', { value: 'audit_only' }, t('shellGuard.audit_only') || 'Audit Only (Log warning)')
                )
              ),
              React.createElement('div', { className: 'sa-field-desc' }, t('shellGuardModeDesc') || 'Enforce mode blocks dangerous shell commands; Audit-only logs warning without blocking.')
            )
          ),
          React.createElement('div', { className: 'sa-field', style: { marginTop: '4px' } },
            React.createElement('div', { className: 'sa-field-label' }, t('customBlockedCommands') || 'Custom Blocked Command Patterns'),
            React.createElement('div', { className: 'sa-field-desc' }, t('customBlockedCommandsDesc') || 'Regular expressions or command substrings to block (one pattern per line).'),
            React.createElement('textarea', {
              className: 'sa-textarea',
              rows: 2,
              disabled: !isReady || saving,
              placeholder: '^sudo\\s+iptables\\nshutdown\\nreboot',
              value: draft.customBlockedCommands || '',
              onChange: (e) => setDraft({ ...draft, customBlockedCommands: e.target.value })
            })
          )
        ),

        // Section 2: Code-Security Diff Gate & SAST
        React.createElement('div', { className: 'sa-section-card' },
          React.createElement('div', { className: 'sa-section-title' },
            '🔍 ' + (t('sec.diff_gate_title') || 'Code-Security Diff Gate & SAST')
          ),
          React.createElement('div', { className: 'sa-section-desc' },
            t('sec.diff_gate_desc') || 'Pre-approval multi-pattern analysis for source modifications, SAST vulnerabilities and prompt injection.'
          ),
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
                React.createElement('span', { className: 'sa-field-label' }, t('strictSecrets') || 'Strict secret scanning'),
                React.createElement('input', {
                  type: 'checkbox',
                  disabled: !isReady || saving,
                  checked: !!draft.strictSecretScanning,
                  onChange: (e) => setDraft({ ...draft, strictSecretScanning: e.target.checked })
                })
              ),
              React.createElement('div', { className: 'sa-field-desc' }, t('strictSecretsDesc') || 'Block execution if API keys or private tokens detected in diff')
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
          ),

          // Diff Gate Visual Inspector (Feature 3)
          topFinding ? React.createElement('div', {
            style: {
              marginTop: '8px',
              padding: '12px 14px',
              borderRadius: '8px',
              backgroundColor: 'var(--dsw-alias-bg-layer-2)',
              border: '1px solid ' + (audit.level === 'red' ? 'var(--dsw-alias-state-error-primary)' : 'var(--dsw-alias-state-warning-primary)')
            }
          },
            React.createElement('div', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' } },
              React.createElement('div', { style: { fontWeight: 600, fontSize: '12px', color: 'var(--dsw-alias-label-primary)' } },
                (t('diffInspector.title') || 'Diff Gate Active Finding: ') + (topFinding.label || topFinding.ruleId || 'Security Finding')
              ),
              React.createElement('span', { className: audit.level === 'red' ? 'sa-badge sa-badge-bad' : 'sa-badge sa-badge-warn' },
                audit.level === 'red' ? (t('diffGate.block') || 'Block') : (t('diffGate.warning') || 'Warning')
              )
            ),
            topFinding.explanation ? React.createElement('div', { style: { fontSize: '11px', color: 'var(--dsw-alias-label-secondary)', marginBottom: '4px' } },
              topFinding.explanation
            ) : null,
            topFinding.match ? React.createElement('pre', {
              style: {
                margin: '4px 0',
                padding: '6px 8px',
                borderRadius: '4px',
                background: 'var(--dsw-alias-bg-layer-3)',
                border: '1px solid var(--dsw-alias-border-l2)',
                fontSize: '11px',
                fontFamily: 'monospace',
                overflowX: 'auto',
                color: 'var(--dsw-alias-label-primary)'
              }
            }, topFinding.match) : null,
            topFinding.remediation ? React.createElement('div', {
              style: { fontSize: '11px', color: 'var(--dsw-alias-state-brand-primary)', marginTop: '4px', fontWeight: 500 }
            }, '💡 ' + (t('diffInspector.remediation') || 'Safe Remediation: ') + topFinding.remediation) : null
          ) : null
        ),

        // Section 3: File Integrity & Sensitive Path Monitor (Feature 4)
        React.createElement('div', { className: 'sa-section-card' },
          React.createElement('div', { className: 'sa-section-title' },
            '🔒 ' + (t('sec.file_integrity_title') || 'File Integrity & Sensitive Path Monitor')
          ),
          React.createElement('div', { className: 'sa-section-desc' },
            t('sec.file_integrity_desc') || 'Guards against unauthorized read or modification of critical credentials, configuration files, and anchors.'
          ),
          React.createElement('div', { className: 'sa-field' },
            React.createElement('div', { className: 'sa-field-label' }, t('sensitivePathPatterns') || 'Custom Sensitive Path Patterns'),
            React.createElement('div', { className: 'sa-field-desc' }, t('sensitivePathPatternsDesc') || 'Monitored file masks or regular expressions (one per line, e.g. .env*, *credentials*, id_rsa, settings.yaml).'),
            React.createElement('textarea', {
              className: 'sa-textarea',
              rows: 2,
              disabled: !isReady || saving,
              placeholder: '.env*\\n*credentials*\\nid_rsa\\nserver.key',
              value: draft.sensitivePathPatterns || '',
              onChange: (e) => setDraft({ ...draft, sensitivePathPatterns: e.target.value })
            })
          )
        ),

        // Section 4: Real-Time Interception Feed & Audit Trail (Feature 1)
        React.createElement('div', { className: 'sa-section-card' },
          React.createElement('div', { className: 'sa-section-title' },
            React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' } },
              '⚡ ' + (t('sec.feed_title') || 'Recent Interceptions & Audit Trail')
            ),
            React.createElement('button', {
              type: 'button',
              className: 'sa-btn',
              onClick: () => fetchEvents(eventsFilter),
              disabled: eventsLoading,
              style: { padding: '3px 8px', fontSize: '11px' }
            },
              React.createElement(RefreshIcon, { size: 11 }),
              eventsLoading ? (t('loading') || 'Loading…') : (t('feed.refresh') || 'Refresh')
            )
          ),
          React.createElement('div', { className: 'sa-section-desc' },
            t('sec.feed_desc') || 'Live audit records of tool calls, guard intercepts, and risk evaluations with threat filtering.'
          ),
          React.createElement('div', { style: { display: 'flex', gap: '6px', margin: '4px 0' } },
            [
              { id: 'all', label: t('filter.all') || 'All' },
              { id: 'guard', label: t('filter.guard') || 'Shell Guard' },
              { id: 'diff_gate', label: t('filter.diff_gate') || 'Diff Gate' },
              { id: 'high_risk', label: t('filter.high_risk') || 'High Risk' }
            ].map(f => React.createElement('button', {
              key: f.id,
              type: 'button',
              className: 'sa-filter-pill' + (eventsFilter === f.id ? ' active' : ''),
              onClick: () => { setEventsFilter(f.id); fetchEvents(f.id); }
            }, f.label))
          ),
          events.length > 0 ? React.createElement('div', {
            style: { display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '240px', overflowY: 'auto' }
          },
            events.map((ev, i) => {
              const isBlocked = ev.blockedByGuard !== undefined;
              const isHigh = (ev.score || 0) >= 40;
              const pillClass = isBlocked ? 'sa-badge sa-badge-bad' : (isHigh ? 'sa-badge sa-badge-warn' : 'sa-badge sa-badge-ok');
              const isExp = expandedEvent === (ev.callId || i);

              return React.createElement('div', {
                key: ev.callId || i,
                className: 'sa-feed-item',
                onClick: () => setExpandedEvent(isExp ? null : (ev.callId || i))
              },
                React.createElement('div', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' } },
                  React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' } },
                    React.createElement('span', { className: pillClass }, isBlocked ? (t('feed.blocked') || 'BLOCKED') : (ev.score !== undefined ? ev.score : 'OK')),
                    React.createElement('strong', { style: { fontSize: '12px', color: 'var(--dsw-alias-label-primary)' } }, ev.toolName || 'tool')
                  ),
                  React.createElement('div', { style: { fontSize: '11px', color: 'var(--dsw-alias-label-secondary)' } },
                    ev.time ? ev.time.slice(11, 19) : ''
                  )
                ),
                ev.blockedByGuard ? React.createElement('div', { style: { fontSize: '11px', color: 'var(--dsw-alias-state-error-primary)', marginTop: '4px' } },
                  ev.blockedByGuard
                ) : null,
                isExp ? React.createElement('div', {
                  style: { marginTop: '8px', paddingTop: '6px', borderTop: '1px dashed var(--dsw-alias-border-l2)', fontSize: '11px', color: 'var(--dsw-alias-label-secondary)' }
                },
                  ev.tags && ev.tags.length ? React.createElement('div', null, 'Tags: ' + ev.tags.join(', ')) : null,
                  ev.reasons && ev.reasons.length ? React.createElement('div', null, 'Reasons: ' + ev.reasons.join('; ')) : null,
                  ev.args ? React.createElement('pre', {
                    style: { margin: '4px 0 0', padding: '4px', background: 'var(--dsw-alias-bg-layer-3)', borderRadius: '4px', overflowX: 'auto', fontFamily: 'monospace' }
                  }, JSON.stringify(ev.args, null, 2)) : null
                ) : null
              );
            })
          ) : React.createElement('div', {
            style: { textAlign: 'center', padding: '16px', fontSize: '12px', color: 'var(--dsw-alias-label-secondary)' }
          }, t('feed.empty') || 'No audit events recorded for this filter.')
        ),

        // Section 5: Audit Trail & Storage
        React.createElement('div', { className: 'sa-section-card' },
          React.createElement('div', { className: 'sa-section-title' },
            '📁 ' + (t('sec.audit_log_title') || 'Audit Trail & Storage')
          ),
          React.createElement('div', { className: 'sa-section-desc' },
            t('sec.audit_log_desc') || 'Persistent JSONL telemetry log with automated gzip rotation and lifecycle retention.'
          ),
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
                React.createElement('span', { className: 'sa-field-label' }, t('auditBadge') || 'Audit shield chip'),
                React.createElement('input', {
                  type: 'checkbox',
                  disabled: !isReady || saving,
                  checked: !!draft.enableAuditBadge,
                  onChange: (e) => setDraft({ ...draft, enableAuditBadge: e.target.checked })
                })
              ),
              React.createElement('div', { className: 'sa-field-desc' }, t('auditBadgeDesc') || 'Display security status shield badge in chat session header utilities')
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

        // Section 6: Live Telemetry & Diagnostics
        audit.hits && audit.hits.length ? React.createElement('div', { className: 'sa-section-card' },
          React.createElement('div', { className: 'sa-section-title' },
            '📊 ' + (t('lastAudit') || 'Live Telemetry & Diagnostics'),
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

      return React.createElement('div', {
        className: 'sa-section-card',
        style: { marginBottom: '16px' }
      },
        React.createElement('div', {
          onClick: () => setOpen(!open),
          style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer', userSelect: 'none' }
        },
          React.createElement('div', { style: { display: 'flex', alignItems: 'center', gap: '10px' } },
            React.createElement('div', {
              style: {
                width: '34px',
                height: '34px',
                borderRadius: '8px',
                backgroundColor: 'var(--dsw-alias-bg-layer-2)',
                border: '1px solid var(--dsw-alias-border-l2)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }
            }, React.createElement(ShieldIcon, { level: 'green', size: 18 })),
            React.createElement('div', null,
              React.createElement('div', { style: { fontWeight: 600, fontSize: '14px', color: 'var(--dsw-alias-label-primary)' } },
                t('title') || 'Shadow Security Auditor'
              ),
              React.createElement('div', { style: { fontSize: '12px', color: 'var(--dsw-alias-label-secondary)' } },
                t('subtitle') || 'Secrets, dangerous command prevention & code diff gate'
              )
            )
          ),
          React.createElement('span', {
            style: { transform: open ? 'rotate(180deg)' : 'none', transition: 'transform .16s', color: 'var(--dsw-alias-label-secondary)' }
          }, React.createElement(Chevron))
        ),
        open ? React.createElement('div', { style: { marginTop: '16px' } },
          React.createElement(SettingsPage, { ...props, ctx })
        ) : null
      );
    }

    module.exports.inject = ['slots', 'locale', 'settingsScope'];
    const dictionaries = {
      en: {
            title: 'Shadow Security Auditor',
            subtitle: 'Secrets, dangerous command prevention & code diff gate',
            'header.sub': 'Real-time security auditing, secret leak prevention, destructive command interception, and code diff gating.',
            'sec.guards_title': 'Execution Safety & Guards',
            'sec.guards_desc': 'Proactive boundary checks intercepting dangerous operations before command execution.',
            'sec.diff_gate_title': 'Code-Security Diff Gate & SAST',
            'sec.diff_gate_desc': 'Pre-approval multi-pattern analysis for source modifications, SAST vulnerabilities and prompt injection.',
            'sec.file_integrity_title': 'File Integrity & Sensitive Path Monitor',
            'sec.file_integrity_desc': 'Guards against unauthorized read or modification of critical credentials, configuration files, and anchors.',
            'sec.feed_title': 'Recent Interceptions & Audit Trail',
            'sec.feed_desc': 'Live audit records of tool calls, guard intercepts, and risk evaluations with threat filtering.',
            'sec.audit_log_title': 'Audit Trail & Storage',
            'sec.audit_log_desc': 'Persistent JSONL telemetry log with automated gzip rotation and lifecycle retention.',
            saved: 'Settings saved',
            save: 'Save Changes',
            saving: 'Saving…',
            loading: 'Loading…',
            unavailable: 'Settings service is currently unavailable (read-only mode).',
            strictSecrets: 'Strict secret scanning',
            strictSecretsDesc: 'Block execution if API keys or private tokens detected in diff',
            blockCommands: 'Block dangerous commands',
            blockCommandsDesc: 'Checks --force, rm -rf, systemctl, DB drop, curl|bash, exfiltration',
            shellGuardMode: 'Shell Guard Policy',
            shellGuardModeDesc: 'Enforce mode blocks dangerous shell commands; Audit-only logs warning without blocking.',
            'shellGuard.enforce': 'Enforce (Block execution)',
            'shellGuard.audit_only': 'Audit Only (Log warning)',
            customBlockedCommands: 'Custom Blocked Command Patterns',
            customBlockedCommandsDesc: 'Regular expressions or command substrings to block (one pattern per line).',
            diffGateMode: 'Diff Gate Policy',
            diffGateModeDesc: 'Diff/approval boundary gate policy: warning or block on high/critical findings',
            'diffGate.disabled': 'Disabled',
            'diffGate.warning': 'Warning (Audit)',
            'diffGate.block': 'Block (Strict)',
            enableSast: 'Insecure code patterns (SAST)',
            enableSastDesc: 'Inspect diffs for SQLi, command injection, path traversal, and eval()',
            enablePromptInjection: 'Prompt-injection scanner',
            enablePromptInjectionDesc: 'Scan diffs for adversarial system prompt override and jailbreak attempts',
            sensitivePathPatterns: 'Custom Sensitive Path Patterns',
            sensitivePathPatternsDesc: 'Monitored file masks or regular expressions (one per line, e.g. .env*, *credentials*, id_rsa, settings.yaml).',
            auditBadge: 'Audit shield chip',
            auditBadgeDesc: 'Display security status shield badge in chat session header',
            enableAuditLog: 'Record audit log',
            enableAuditLogDesc: 'Maintain persistent JSONL audit trail with automated rotation',
            maxFileSizeMb: 'Max log file size (MB)',
            maxFileSizeMbDesc: 'Compress log to gzip archive when size exceeds this limit',
            retentionDays: 'Log retention (days)',
            retentionDaysDesc: 'Automatically remove gzip archives older than this threshold',
            lastAudit: 'Last audit',
            'action.export_json': 'Export JSON',
            'action.export_bill': 'Export Bill (MD)',
            'filter.all': 'All',
            'filter.guard': 'Shell Guard',
            'filter.diff_gate': 'Diff Gate',
            'filter.high_risk': 'High Risk',
            'feed.refresh': 'Refresh',
            'feed.blocked': 'BLOCKED',
            'feed.empty': 'No audit events recorded for this filter.',
            'diffInspector.title': 'Diff Gate Active Finding: ',
            'diffInspector.remediation': 'Safe Remediation: ',
            'update.available': 'Update available: v{latestVersion} (current: v{currentVersion})',
            'update.btn': 'Update Now',
            'update.updating': 'Updating…',
            'update.done': 'Successfully updated to v{version}! Please restart DSH.',
            'update.failed': 'Update failed: {error}',
            'update.checking': 'Checking for updates…',
            'update.up_to_date': 'Up to date',
            'shield.green': 'Safe',
            'shield.yellow': 'Warning',
            'shield.red': 'Alert'
          },
          zh: {
            title: '影子安全审计器',
            subtitle: '密钥防泄漏、高危命令拦截与代码差异网关',
            'header.sub': '实时安全审计、机密防泄漏、破坏性命令拦截与代码差异安全把关。',
            'sec.guards_title': '执行安全与防护',
            'sec.guards_desc': '在命令执行前主动拦截破坏性操作与高危命令。',
            'sec.diff_gate_title': '代码安全差异网关与 SAST',
            'sec.diff_gate_desc': '代码变更预检：扫描静态代码漏洞、硬编码密钥与提示词注入风险。',
            'sec.file_integrity_title': '文件完整性与敏感路径监控',
            'sec.file_integrity_desc': '防止未授权读取或篡改关键凭据、配置文件与系统锚点。',
            'sec.feed_title': '实时拦截与审计日志',
            'sec.feed_desc': '工具调用、防护拦截和风险评估的实时日志，支持分类过滤。',
            'sec.audit_log_title': '审计日志与存储',
            'sec.audit_log_desc': '持久化 JSONL 审计轨迹，支持自动 gzip 轮转与过期清理。',
            saved: '设置已保存',
            save: '保存更改',
            saving: '保存中…',
            loading: '加载中…',
            unavailable: '配置服务暂不可用（只读模式）。',
            strictSecrets: '严格密钥扫描',
            strictSecretsDesc: '在代码差异中检测到 API Key 或私钥时阻止执行',
            blockCommands: '拦截高危命令',
            blockCommandsDesc: '检查 --force、rm -rf、systemctl、DROP DB、curl|bash 及远程外发',
            shellGuardMode: 'Shell 防护策略',
            shellGuardModeDesc: '强制模式完全阻止命令执行；仅审计模式记录告警日志但不阻断。',
            'shellGuard.enforce': '强制执行（阻断）',
            'shellGuard.audit_only': '仅审计（记录告警）',
            customBlockedCommands: '自定义禁止命令规则',
            customBlockedCommandsDesc: '要禁止的正则表达式或命令子串（每行一条）。',
            diffGateMode: 'Diff Gate 策略',
            diffGateModeDesc: '差异网关策略：发现高危/严重风险时告警或严格阻断',
            'diffGate.disabled': '已禁用',
            'diffGate.warning': '告警（审计）',
            'diffGate.block': '阻断（严格）',
            enableSast: '不安全代码模式 (SAST)',
            enableSastDesc: '检查代码差异中的 SQL 注入、命令注入、路径穿越和 eval()',
            enablePromptInjection: '提示词注入扫描器',
            enablePromptInjectionDesc: '扫描代码差异中的系统提示词覆盖与越狱提权尝试',
            sensitivePathPatterns: '自定义敏感路径规则',
            sensitivePathPatternsDesc: '重点监控的文件通配符或正则（每行一条，如 .env*, *credentials*, id_rsa, settings.yaml）。',
            auditBadge: '安全盾牌徽章',
            auditBadgeDesc: '在聊天会话顶部工具栏显示安全状态徽章',
            enableAuditLog: '记录审计日志',
            enableAuditLogDesc: '维护持久化 JSONL 审计日志并自动轮转',
            maxFileSizeMb: '日志最大容量 (MB)',
            maxFileSizeMbDesc: '日志超过该大小时自动压缩归档为 gzip',
            retentionDays: '日志保留天数',
            retentionDaysDesc: '自动删除超过该天数的归档压缩包',
            lastAudit: '最近审计',
            'action.export_json': '导出 JSON',
            'action.export_bill': '导出对账单 (MD)',
            'filter.all': '全部',
            'filter.guard': 'Shell 防护',
            'filter.diff_gate': '差异网关',
            'filter.high_risk': '高风险',
            'feed.refresh': '刷新',
            'feed.blocked': '已阻断',
            'feed.empty': '当前过滤条件下无审计事件。',
            'diffInspector.title': '差异网关检测项：',
            'diffInspector.remediation': '安全修复建议：',
            'update.available': '发现新版本 v{latestVersion}（当前版本 v{currentVersion}）',
            'update.btn': '立即更新',
            'update.updating': '正在更新…',
            'update.done': '更新成功至 v{version}！请重启 DSH 服务生效。',
            'update.failed': '更新失败：{error}',
            'update.checking': '正在检查更新…',
            'update.up_to_date': '已是最新版本',
            'shield.green': '安全',
            'shield.yellow': '警告',
            'shield.red': '告警'
          }
    };

    module.exports.apply = function apply(ctx) {
      const registerDictionaries = () => {
        try {
          if (!ctx.locale || typeof ctx.locale.register !== 'function') return () => {};
          // Support both DSH signatures: register(NS, { en, zh }) and register(NS, locale, dict)
          if (ctx.locale.register.length >= 3) {
            const undoEn = ctx.locale.register(NS, 'en', dictionaries.en);
            const undoZh = ctx.locale.register(NS, 'zh', dictionaries.zh);
            return () => {
              try { typeof undoEn === 'function' && undoEn(); } catch (_) {}
              try { typeof undoZh === 'function' && undoZh(); } catch (_) {}
            };
          }
          const undo = ctx.locale.register(NS, { en: dictionaries.en, zh: dictionaries.zh });
          return () => {
            try { typeof undo === 'function' && undo(); } catch (_) {}
          };
        } catch (err) {
          ctx.logger?.debug?.('[shadow-auditor] UI locale registration skipped or already registered (error type: ' + (err?.name || 'Error') + ').');
          return () => {};
        }
      };

      if (typeof ctx.effect === 'function') {
        ctx.effect(() => {
          const undo = registerDictionaries();
          return () => { try { typeof undo === 'function' && undo(); } catch (_) {} };
        }, 'dsh-shadow-auditor: locale dictionaries');
      } else {
        registerDictionaries();
      }

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
      } catch (err) {
        ctx.logger?.debug?.('[shadow-auditor] UI slot registration failed (error type: ' + (err?.name || 'Error') + ').');
      }
    };
    return module.exports;
  }
});
