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

    function PluginCard({ ctx }) {
      const [expanded, setExpanded] = React.useState(false);
      const [snap, setSnap] = React.useState({ status: 'loading', value: null, writable: false });
      const [draft, setDraft] = React.useState({
        strictSecretScanning: true,
        blockDangerousCommands: true,
        enableAuditBadge: true,
        enableAuditLog: true,
        maxFileSizeMb: 50,
        retentionDays: 30,
      });
      const [saving, setSaving] = React.useState(false);
      const [msg, setMsg] = React.useState('');
      const [audit, setAudit] = React.useState({ level: 'green', hits: [] });

      const initializedRef = React.useRef(false);

      // hooks must be above any return
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
              });
            }
          };
          update();
          if (scope.subscribe) off = scope.subscribe(update);
        } catch (_) { setSnap({ status: 'unavailable', value: null, writable: false }); }
        return () => { try { off && off(); } catch {} };
      }, []);

      // fetch audit only when expanded
      React.useEffect(() => {
        if (!expanded) return;
        let alive = true;
        const fetchAudit = () => {
          fetch('/dsh-shadow-auditor/audit', { headers: { accept: 'application/json' } })
            .then((r) => r.ok ? r.json() : null)
            .then((j) => { if (alive && j && j.level) setAudit(j); })
            .catch(() => {});
        };
        fetchAudit();
        const iv = setInterval(fetchAudit, 3000);
        return () => { alive = false; clearInterval(iv); };
      }, [expanded]);

      const t = (() => { try { return ctx.locale && ctx.locale.bind ? ctx.locale.bind(NS) : (k) => k; } catch (_) { return (k) => k; } })();

      const onSave = async () => {
        if (snap.status !== 'ready') return;
        setSaving(true); setMsg('');
        try {
          if (!ctx.settingsScope || !ctx.settingsScope.bind) {
            setMsg(t('unavailable') || 'Settings service unavailable');
            setSaving(false);
            return;
          }
          const scope = ctx.settingsScope.bind({ namespace: NS });
          const errors = [];
          for (const key of ['strictSecretScanning', 'blockDangerousCommands', 'enableAuditBadge', 'enableAuditLog', 'maxFileSizeMb', 'retentionDays']) {
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

      const levelLabel = audit.level === 'red' ? 'RED' : audit.level === 'yellow' ? 'YELLOW' : 'GREEN';
      const badgeClass = audit.level === 'red' ? 'sa-badge sa-badge-red' : audit.level === 'yellow' ? 'sa-badge sa-badge-yellow' : 'sa-badge sa-badge-green';
      const isReady = snap.status === 'ready';

      return React.createElement('div', { className: 'sa-card' },
        React.createElement('style', { 'data-dsh-plugin': 'dsh-shadow-auditor' },
          '.sa-card{border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);border-radius:12px;list-style:none}' +
          '.sa-head{appearance:none;width:100%;font:inherit;color:inherit;text-align:left;cursor:pointer;background:0 0;border:0;border-radius:12px;display:flex;align-items:center;gap:12px;padding:14px 16px}' +
          '.sa-title{color:var(--dsw-alias-label-primary);font-size:15px;font-weight:600;line-height:1.4}' +
          '.sa-sub{color:var(--dsw-alias-label-secondary);font-size:13px}' +
          '.sa-body{border-top:1px solid var(--dsw-alias-border-l2);margin:0 16px;padding-bottom:8px}' +
          '.sa-field{display:flex;flex-direction:column;gap:6px;padding:12px 0}' +
          '.sa-row{display:flex;align-items:center;justify-content:space-between;gap:12px}' +
          '.sa-input{height:34px;width:120px;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);color:var(--dsw-alias-label-primary);border-radius:8px;padding:0 12px;font-size:13px}' +
          '.sa-input:disabled{opacity:0.6;cursor:not-allowed}' +
          '.sa-foot{border-top:1px solid var(--dsw-alias-border-l2);display:flex;justify-content:flex-end;align-items:center;gap:8px;padding:12px 0 4px}' +
          '.sa-save{appearance:none;font:inherit;cursor:pointer;border:1px solid transparent;border-radius:8px;padding:5px 14px;font-size:13px;background:var(--dsw-alias-label-primary);color:var(--dsw-alias-bg-layer-3)}' +
          '.sa-save:disabled{opacity:0.5;cursor:not-allowed}' +
          '.sa-chev{margin-left:auto;flex:none;color:var(--dsw-alias-label-tertiary);transition:transform .16s}' +
          '.sa-chev-open{transform:rotate(180deg)}' +
          '.sa-warn{color:var(--dsw-alias-color-warning,#d9a400);font-size:13px;padding:8px 0}' +
          '.sa-badge{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px;border:1px solid var(--dsw-alias-border-l2)}' +
          '.sa-badge-red{background:var(--dsw-alias-color-danger,#e5534b);color:var(--dsw-alias-bg-layer-3,#fff);border-color:var(--dsw-alias-color-danger,#e5534b)}' +
          '.sa-badge-yellow{background:var(--dsw-alias-color-warning,#d9a400);color:var(--dsw-alias-bg-layer-3,#fff);border-color:var(--dsw-alias-color-warning,#d9a400)}' +
          '.sa-badge-green{background:var(--dsw-alias-color-success,#2da44e);color:var(--dsw-alias-bg-layer-3,#fff);border-color:var(--dsw-alias-color-success,#2da44e)}'
        ),
        React.createElement('button', { className: 'sa-head', onClick: () => setExpanded(!expanded), 'aria-expanded': expanded },
          React.createElement('span', { className: 'sa-title' }, t('title') || 'Shadow Security Auditor'),
          React.createElement('span', { className: 'sa-sub', style: { marginLeft: 8 } }, t('subtitle') || 'Secrets & command safety'),
          React.createElement('span', { className: badgeClass, style: { marginLeft: 'auto' } }, levelLabel),
          React.createElement(Chevron, { style: {}, className: 'sa-chev' + (expanded ? ' sa-chev-open' : '') })
        ),
        expanded ? React.createElement('div', { className: 'sa-body' },
          snap.status === 'loading' ? React.createElement('div', { className: 'sa-field', style: { color: 'var(--dsw-alias-label-secondary)', fontSize: 13 } }, t('loading') || 'Loading…') : null,
          snap.status === 'unavailable' ? React.createElement('div', { className: 'sa-warn' }, t('unavailable') || 'Settings service is currently unavailable (read-only mode).') : null,
          snap.status !== 'loading' ? React.createElement('div', null,
            React.createElement('div', { className: 'sa-field' },
              React.createElement('label', { className: 'sa-row' },
                React.createElement('span', null, t('strictSecrets') || 'Strict secret scanning'),
                React.createElement('input', {
                  type: 'checkbox',
                  disabled: !isReady || saving,
                  checked: !!draft.strictSecretScanning,
                  onChange: (e) => setDraft({ ...draft, strictSecretScanning: e.target.checked })
                })
              ),
              React.createElement('div', { className: 'sa-sub' }, t('strictSecretsDesc') || 'Block on API keys / private tokens in diff')
            ),
            React.createElement('div', { className: 'sa-field' },
              React.createElement('label', { className: 'sa-row' },
                React.createElement('span', null, t('blockCommands') || 'Block dangerous commands'),
                React.createElement('input', {
                  type: 'checkbox',
                  disabled: !isReady || saving,
                  checked: !!draft.blockDangerousCommands,
                  onChange: (e) => setDraft({ ...draft, blockDangerousCommands: e.target.checked })
                })
              ),
              React.createElement('div', { className: 'sa-sub' }, t('blockCommandsDesc') || 'Checks --force, rm -rf, systemctl, DB drop, curl|bash, exfiltration')
            ),
            React.createElement('div', { className: 'sa-field' },
              React.createElement('label', { className: 'sa-row' },
                React.createElement('span', null, t('auditBadge') || 'Audit badge'),
                React.createElement('input', {
                  type: 'checkbox',
                  disabled: !isReady || saving,
                  checked: !!draft.enableAuditBadge,
                  onChange: (e) => setDraft({ ...draft, enableAuditBadge: e.target.checked })
                })
              ),
              React.createElement('div', { className: 'sa-sub' }, t('auditBadgeDesc') || 'Display security status shield badge in approval dialogs')
            ),
            React.createElement('div', { className: 'sa-field' },
              React.createElement('label', { className: 'sa-row' },
                React.createElement('span', null, t('enableAuditLog') || 'Record audit log'),
                React.createElement('input', {
                  type: 'checkbox',
                  disabled: !isReady || saving,
                  checked: !!draft.enableAuditLog,
                  onChange: (e) => setDraft({ ...draft, enableAuditLog: e.target.checked })
                })
              ),
              React.createElement('div', { className: 'sa-sub' }, t('enableAuditLogDesc') || 'Maintain persistent JSONL audit trail with automated rotation')
            ),
            React.createElement('div', { className: 'sa-field' },
              React.createElement('div', { className: 'sa-row' },
                React.createElement('span', null, t('maxFileSizeMb') || 'Max log file size (MB)'),
                React.createElement('input', {
                  className: 'sa-input',
                  type: 'number',
                  min: 1,
                  max: 1000,
                  disabled: !isReady || saving,
                  value: Number(draft.maxFileSizeMb) || 50,
                  onChange: (e) => setDraft({ ...draft, maxFileSizeMb: Math.max(1, Number(e.target.value) || 50) })
                })
              ),
              React.createElement('div', { className: 'sa-sub' }, t('maxFileSizeMbDesc') || 'Compress log to gzip archive when size exceeds this limit')
            ),
            React.createElement('div', { className: 'sa-field' },
              React.createElement('div', { className: 'sa-row' },
                React.createElement('span', null, t('retentionDays') || 'Log retention (days)'),
                React.createElement('input', {
                  className: 'sa-input',
                  type: 'number',
                  min: 1,
                  max: 365,
                  disabled: !isReady || saving,
                  value: Number(draft.retentionDays) || 30,
                  onChange: (e) => setDraft({ ...draft, retentionDays: Math.max(1, Number(e.target.value) || 30) })
                })
              ),
              React.createElement('div', { className: 'sa-sub' }, t('retentionDaysDesc') || 'Automatically remove gzip archives older than this threshold')
            ),
            audit.hits && audit.hits.length ? React.createElement('div', { className: 'sa-field', style: { fontSize: 12, color: 'var(--dsw-alias-label-secondary)' } },
              React.createElement('div', { style: { fontWeight: 600 } }, (t('lastAudit') || 'Last audit') + ': ' + audit.level + (audit.source ? ' (' + audit.source + ')' : '')),
              React.createElement('ul', { style: { margin: '6px 0 0 16px' } }, audit.hits.slice(0, 5).map((h, i) => React.createElement('li', { key: i }, (h.label || h.type || h.id) + ': ' + String(h.match).slice(0, 60))))
            ) : null,
            React.createElement('div', { className: 'sa-foot' },
              msg ? React.createElement('span', { style: { fontSize: 12, color: 'var(--dsw-alias-label-secondary)', marginRight: 'auto' } }, msg) : null,
              React.createElement('button', { className: 'sa-save', onClick: onSave, disabled: !isReady || saving }, saving ? (t('saving') || 'Saving…') : (t('save') || 'Save'))
            )
          ) : null
        ) : null
      );
    }

    module.exports.inject = ['slots', 'locale', 'settingsScope'];
    module.exports.apply = function apply(ctx) {
      try {
        ctx.locale.register(NS, {
          en: {
            title: 'Shadow Security Auditor',
            subtitle: 'Secrets & command safety',
            saved: 'Saved',
            strictSecrets: 'Strict secret scanning',
            strictSecretsDesc: 'Block on API keys / private tokens in diff',
            blockCommands: 'Block dangerous commands',
            blockCommandsDesc: 'Checks --force, rm -rf, systemctl, DB drop, curl|bash, exfiltration',
            auditBadge: 'Audit badge',
            auditBadgeDesc: 'Display security shield badge in approval dialogs',
            enableAuditLog: 'Record audit log',
            enableAuditLogDesc: 'Maintain persistent JSONL audit trail with automated rotation',
            maxFileSizeMb: 'Max log file size (MB)',
            maxFileSizeMbDesc: 'Compress log to gzip archive when size exceeds this limit',
            retentionDays: 'Log retention (days)',
            retentionDaysDesc: 'Automatically remove gzip archives older than this threshold',
            loading: 'Loading…',
            unavailable: 'Settings service is currently unavailable (read-only mode).',
            save: 'Save',
            saving: 'Saving…',
            lastAudit: 'Last audit',
          },
          ru: {
            title: 'Теневой аудитор безопасности',
            subtitle: 'Защита от утечек секретов и опасных команд',
            saved: 'Сохранено',
            strictSecrets: 'Строгое сканирование секретов',
            strictSecretsDesc: 'Блокировать фиксацию API-ключей и токенов в дифах',
            blockCommands: 'Блокировать опасные команды',
            blockCommandsDesc: 'Перехват --force, rm -rf, systemctl, DROP DB, curl|bash, эксфильтрации',
            auditBadge: 'Бейдж аудита',
            auditBadgeDesc: 'Отображать бейдж статуса безопасности в диалогах подтверждения',
            enableAuditLog: 'Запись журнала аудита',
            enableAuditLogDesc: 'Вести персистентный JSONL-журнал с автоматической ротацией',
            maxFileSizeMb: 'Макс. размер файла лога (МБ)',
            maxFileSizeMbDesc: 'Архивировать в gzip при превышении данного размера',
            retentionDays: 'Хранение логов (дней)',
            retentionDaysDesc: 'Автоматически удалять gzip-архивы старше заданного срока',
            loading: 'Загрузка…',
            unavailable: 'Сервис настроек недоступен (режим только для чтения).',
            save: 'Сохранить',
            saving: 'Сохранение…',
            lastAudit: 'Последний аудит',
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
        }
      } catch (_) {}
    };
    return module.exports;
  }
});