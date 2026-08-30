import { Schema } from '@deepseek-ai/schemastery';

export const name = '@goodandready-private/dsh-shadow-auditor';
export const inject = ['tools', 'settings', 'webServer'];

export const Config = Schema.object({
  strictSecretScanning: Schema.boolean().default(true).description("Block execution if API keys or private tokens detected in diff"),
  blockDangerousCommands: Schema.boolean().default(true).description("Block destructive flags like --force, rm -rf /, etc."),
  enableAuditBadge: Schema.boolean().default(true).description("Display security shield badge in approval dialogs")
});

const NS = '@goodandready-private/dsh-shadow-auditor';

export function apply(ctx, config) {
  let getConfig = () => config;

  ctx.inject(['settings'], (sctx) => {
    const scope = sctx.settings.register(NS, Config, { base: config });
    getConfig = () => scope.get() ?? config;
  });

  if (ctx.tools) {
    ctx.tools.register({
      name: 'shadow_auditor_scan_diff',
      description: 'Initial tool for dsh-shadow-auditor',
      parameters: { type: 'object', properties: {} },
      execute: async () => {
        return { success: true, plugin: 'dsh-shadow-auditor' };
      }
    });
  }
}
