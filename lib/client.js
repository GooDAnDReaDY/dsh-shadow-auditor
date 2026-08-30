window.__ModuleLoader__.load({
  id: '@goodandready-private/dsh-shadow-auditor',
  factory: (require) => {
    var module = { exports: {} };
    const React = require('react');

    const NS = '@goodandready-private/dsh-shadow-auditor';

    function PluginCard({ ctx }) {
      const [expanded, setExpanded] = React.useState(false);
      return React.createElement('div', { className: 'shadow-auditor-card' },
        React.createElement('button', {
          className: 'shadow-auditor-head',
          onClick: () => setExpanded(!expanded)
        },
          React.createElement('span', { className: 'shadow-auditor-title' }, 'Shadow Security Auditor')
        )
      );
    }

    module.exports.inject = ['slots'];
    module.exports.apply = function apply(ctx) {
      if (ctx.slots) {
        ctx.slots.register({
          name: 'settings.plugin.item',
          key: NS,
          locale: NS,
          inject: () => ({ ctx })
        }, PluginCard);
      }
    };

    return module.exports;
  }
});
