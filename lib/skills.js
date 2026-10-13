/**
 * @file skills.js
 * Runtime skill registration for autonomous DSH agents (#99).
 */

export const SHADOW_AUDIT_REVIEW_SKILL_ID = 'shadow-audit-review';

export const SHADOW_AUDIT_REVIEW_INSTRUCTIONS = `# Shadow Audit Review Skill

Use this skill to autonomously audit code changes, terminal commands, and system configuration:

1. Diff Verification:
   - Run shadow_auditor_scan_diff on candidate diffs or text.
   - Block execution if level is 'red' (hardcoded API tokens, credentials).
   - Require user confirmation if level is 'yellow' (internal IP, local infrastructure paths).

2. Command Safety:
   - Run shadow_auditor_check_command before running untrusted shell operations.
   - Inspect flags for destructive operations (rm -rf, mkfs, dd, forkbombs).

3. System Configuration Audit:
   - Run shadow_auditor_system_audit to inspect cordis configuration, patch files, network bindings, and file permissions.
   - Verify loopback-only network bindings (127.0.0.1, localhost) for administrative endpoints.
`;

/**
 * Dynamically registers the shadow-audit-review skill if the skills service is present (#99).
 * Does not throw or fail if the service is not installed (loose coupling).
 *
 * @param {object} ctx - Cordis context
 * @param {object} [options]
 * @returns {boolean} Whether skill was registered synchronously or scheduled
 */
export function registerShadowAuditSkill(ctx, options = {}) {
  const logger = options.logger || ctx?.logger || console;
  const skillDef = {
    id: SHADOW_AUDIT_REVIEW_SKILL_ID,
    name: 'shadow-audit-review',
    description: 'Autonomous security audit review using DSH Shadow Auditor tools and rules',
    instructions: options.instructions || SHADOW_AUDIT_REVIEW_INSTRUCTIONS,
    tools: [
      'shadow_auditor_scan_diff',
      'shadow_auditor_check_command',
      'shadow_auditor_system_audit',
      'shadow_auditor_status'
    ],
    ...options.metadata
  };

  const tryRegister = (target) => {
    if (!target) return false;
    try {
      if (typeof target.register === 'function') {
        target.register(skillDef);
        return true;
      }
      if (typeof target.add === 'function') {
        target.add(skillDef);
        return true;
      }
    } catch (err) {
      logger.debug?.('[shadow-auditor] Failed to register skill: ' + (err?.message || err));
    }
    return false;
  };

  // 1. Direct check
  const directSkills = ctx?.get ? ctx.get('skills') : ctx?.skills;
  if (directSkills) {
    return tryRegister(directSkills);
  }

  // 2. Loose injection when service becomes available
  if (typeof ctx?.inject === 'function') {
    try {
      ctx.inject(['skills'], (sctx) => {
        const s = sctx?.get ? sctx.get('skills') : sctx?.skills;
        if (s) tryRegister(s);
      });
      return true;
    } catch (_) {
      return false;
    }
  }

  return false;
}
