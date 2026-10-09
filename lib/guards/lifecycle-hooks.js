/**
 * @file lifecycle-hooks.js
 * Multi-surface lifecycle interception engine (#108, #109, #110, #111, #124, #125, #126, #135).
 * Enforces security gates at agent/pre-step, tools/guard, tools/pre-execute, and tools/post-execute.
 */

import { scanLineForPromptInjection } from '../diff-gate/prompt-injection.js';
import { scanDiff, scanFileContent } from '../diff-gate/gate.js';
import { maskSecret, SECRET_PATTERNS } from './secrets.js';
import { findDangerous, isSensitivePath } from './command.js';

export function isCriticalThreat(hit) {
  if (!hit) return false;
  const id = String(hit.id || hit.ruleId || '').toLowerCase();
  const label = String(hit.label || hit.name || '').toLowerCase();

  if (id === 'mkfs-dd' || id === 'destructive-delete-protected-prefix' || id === 'destructive-delete-outside-workspace') {
    return true;
  }
  if (id === 'rm-rf' && (label.includes('root') || label.includes('protected'))) {
    return true;
  }
  if (id === 'aws' || id === 'private-key' || id === 'sec-api-key') {
    return true;
  }
  if (id.includes('exfiltration') || label.includes('exfiltration')) {
    return true;
  }
  return false;
}

// Heuristic prompt injection indicators for pre-filtering (#110)
const PROMPT_INJECTION_RULES = [
  { id: 'pi_ignore_instructions', re: /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i, explanation: 'Instruction override attack' },
  { id: 'pi_jailbreak_dan', re: /\b(?:DAN\s+mode|jailbreak|do\s+anything\s+now)\b/i, explanation: 'Jailbreak persona prompt' },
  { id: 'pi_system_leak', re: /(?:print|output|display|reveal|leak)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions)/i, explanation: 'System prompt extraction attempt' },
  { id: 'pi_role_override', re: /\byou\s+are\s+now\s+(?:an\s+unfiltered|an\s+evil|a\s+malicious|no\s+longer)\b/i, explanation: 'Adversarial roleplay hijack' },
  { id: 'pi_hidden_command', re: /<\s*(?:system|assistant|override)\s*>[\s\S]*?<\s*\/\s*(?:system|assistant|override)\s*>/i, explanation: 'Fake delimiter injection tag' }
];

export function extractTextFromMessages(messages) {
  if (!Array.isArray(messages)) return '';
  const chunks = [];
  for (const m of messages) {
    if (!m) continue;
    if (typeof m === 'string') {
      chunks.push(m);
      continue;
    }
    if (typeof m.content === 'string') {
      chunks.push(m.content);
    } else if (Array.isArray(m.content)) {
      for (const block of m.content) {
        if (block && typeof block.text === 'string') {
          chunks.push(block.text);
        }
      }
    }
  }
  return chunks.join('\n');
}

export function stripMessages(messages, stripper) {
  if (!Array.isArray(messages) || !stripper || typeof stripper.strip !== 'function') return messages;
  return messages.map((msg) => {
    if (!msg) return msg;
    if (typeof msg === 'string') {
      return stripper.strip(msg).text;
    }
    if (typeof msg.content === 'string') {
      const stripped = stripper.strip(msg.content);
      if (stripped.strippedCount > 0) {
        return { ...msg, content: stripped.text };
      }
    } else if (Array.isArray(msg.content)) {
      let changed = false;
      const newContent = msg.content.map((block) => {
        if (block && block.type === 'text' && typeof block.text === 'string') {
          const stripped = stripper.strip(block.text);
          if (stripped.strippedCount > 0) {
            changed = true;
            return { ...block, text: stripped.text };
          }
        }
        return block;
      });
      if (changed) {
        return { ...msg, content: newContent };
      }
    }
    return msg;
  });
}

export function scanPromptMessages(messages) {
  const text = extractTextFromMessages(messages);
  if (!text.trim()) return [];
  const findings = [];
  for (const rule of PROMPT_INJECTION_RULES) {
    rule.re.lastIndex = 0;
    const match = rule.re.exec(text);
    if (match) {
      findings.push({
        ruleId: rule.id,
        category: 'prompt-injection',
        explanation: rule.explanation,
        evidence: match[0]
      });
    }
  }
  return findings;
}

export function sanitizeResultText(text) {
  if (typeof text !== 'string' || !text) return text;
  let sanitized = text;
  for (const p of SECRET_PATTERNS) {
    p.regex.lastIndex = 0;
    sanitized = sanitized.replace(p.regex, (m) => maskSecret(m));
  }
  return sanitized;
}

export function sanitizeResultBlocks(content) {
  if (!Array.isArray(content)) return content;
  return content.map((block) => {
    if (block && block.type === 'text' && typeof block.text === 'string') {
      const sanitized = sanitizeResultText(block.text);
      if (sanitized !== block.text) {
        return { ...block, text: sanitized };
      }
    }
    return block;
  });
}

/**
 * Registers mandatory tools.guard with priority prepend and critical-override (#124, #125).
 */
export function registerToolsGuard(ctx, { getConfig, recorder, isCommandTool, isFileReadTool, isFileWriteTool, recordGuardHit, setLastAudit, logger }) {
  if (!ctx || !ctx.tools || typeof ctx.tools.guard !== 'function') return;

  try {
    ctx.effect(() => {
      const off = ctx.tools.guard((execution) => {
        try {
          const cfg = getConfig();
          const name = String(execution.name || '');
          const args = execution.arguments;
          const sessionId = String(execution.agent?.session?.header?.id ?? 'unknown');

          // 1. Shell and execution command guard
          if (isCommandTool(name)) {
            if (cfg.blockDangerousCommands) {
              const cmd = typeof args === 'object' && args !== null
                ? String(args.command || args.cmd || args.CommandLine || '')
                : String(args || '');
              if (cmd.trim()) {
                const cwd = (typeof args === 'object' && args !== null ? (args.cwd || args.Cwd) : null)
                  || execution.agent?.session?.header?.cwd
                  || process.cwd();
                let dryRunHit = null;
                let urlCredHit = null;
                const hit = findDangerous(cmd, {
                  customBlockedCommands: cfg.customBlockedCommands,
                  sensitivePathPatterns: cfg.sensitivePathPatterns,
                  workspace: cwd,
                  logger,
                  onDryRun: (info) => { dryRunHit = info; },
                  onUrlCredentials: (info) => { urlCredHit = info; }
                });
                if (hit) {
                  const isCritical = isCriticalThreat(hit);
                  const forceBlock = cfg.secretBlockCritical !== false && isCritical;
                  const isAuditOnly = !forceBlock && cfg.shellGuardMode === 'audit_only';
                  const isAsk = !forceBlock && cfg.shellGuardMode === 'ask';

                  setLastAudit({ level: isAuditOnly ? 'yellow' : 'red', hits: [hit], at: Date.now(), source: 'guard:command' });
                  if (cfg.enableAuditLog) {
                    recordGuardHit(recorder, {
                      sessionId, callId: execution.callId, toolName: name, args,
                      success: isAuditOnly,
                      blocked: isAuditOnly ? undefined : `${hit.label}: ${String(hit.match).slice(0, 100)}` + (forceBlock ? ' [CRITICAL-FORCED]' : ''),
                      score: 95, tags: ['destructive', 'command-safety'],
                      reason: isAuditOnly
                        ? `Audit-only warning: ${hit.label}`
                        : (forceBlock ? `Unconditional critical block: ${hit.label}` : `Blocked by security guard: ${hit.label}`)
                    });
                  }
                  if (isAsk) {
                    return '\u26a0\ufe0f [shadow-auditor] Approval required (ask): `' + String(hit.match).slice(0, 120) + '` (' + hit.label + ').';
                  }
                  if (!isAuditOnly) {
                    return '\u26d4 [shadow-auditor] Command blocked: `' + String(hit.match).slice(0, 120) + '` (' + hit.label + ').' + (forceBlock ? ' (Critical threat override)' : '');
                  }
                } else if (dryRunHit) {
                  setLastAudit({
                    level: 'green',
                    hits: [{ type: 'dry-run-verification', label: dryRunHit.label, match: dryRunHit.match }],
                    at: Date.now(),
                    source: 'guard:command'
                  });
                  if (cfg.enableAuditLog) {
                    recordGuardHit(recorder, {
                      sessionId, callId: execution.callId, toolName: name, args,
                      success: true,
                      score: 15, tags: ['dry-run-verification'],
                      reason: `Permitted dry-run / explain inspection: ${dryRunHit.label}`
                    });
                  }
                } else if (urlCredHit) {
                  setLastAudit({
                    level: 'yellow',
                    hits: [{ type: 'credential-exposure', label: urlCredHit.label, match: urlCredHit.match }],
                    at: Date.now(),
                    source: 'guard:command'
                  });
                  if (cfg.enableAuditLog) {
                    recordGuardHit(recorder, {
                      sessionId, callId: execution.callId, toolName: name, args,
                      success: true,
                      score: 70, tags: ['credential-exposure'],
                      reason: `Sensitive inline URL credentials detected in command execution: ${urlCredHit.label}`
                    });
                  }
                }
              }
            }
          }

          // 2. Sensitive path monitor for file read
          if (isFileReadTool(name)) {
            let readPath = '';
            if (typeof args === 'string') readPath = args;
            else if (args && typeof args === 'object') {
              readPath = args.path || args.filePath || args.targetFile || args.file || args.AbsolutePath || '';
            }
            if (readPath && isSensitivePath(readPath, cfg.sensitivePathPatterns)) {
              setLastAudit({
                level: 'yellow',
                hits: [{ type: 'file-integrity', label: 'Sensitive path read attempt', match: String(readPath).slice(0, 100) }],
                at: Date.now(),
                source: 'guard:file-read'
              });
              if (cfg.enableAuditLog) {
                recordGuardHit(recorder, {
                  sessionId, callId: execution.callId, toolName: name, args,
                  success: true,
                  score: 45, tags: ['file-integrity', 'sensitive-read'],
                  reason: `Sensitive credential/config path accessed: ${readPath}`
                });
              }
            }
          }

          // 3. Diff Gate check for source edits
          if (isFileWriteTool(name)) {
            const gateMode = cfg.diffGateMode || 'warning';
            if (gateMode !== 'disabled' || cfg.strictSecretScanning) {
              let text = '';
              let targetPath = 'unknown';
              if (typeof args === 'string') {
                text = args;
              } else if (args && typeof args === 'object') {
                targetPath = args.path || args.filePath || args.targetFile || args.file || args.AbsolutePath || 'unknown';
                if (typeof args.content === 'string') text = args.content;
                else if (typeof args.patch === 'string') text = args.patch;
                else if (typeof args.diff === 'string') text = args.diff;
                else if (typeof args.ReplacementContent === 'string') text = args.ReplacementContent;
                else if (typeof args.CodeContent === 'string') text = args.CodeContent;
                else text = JSON.stringify(args);
              }

              const isDiff = text.includes('--- a/') || text.includes('+++ b/') || text.includes('@@');
              const gateOptions = {
                mode: gateMode,
                enableSecrets: cfg.strictSecretScanning,
                enableSast: cfg.enableSastScan !== false,
                enablePromptInjection: cfg.enablePromptInjectionScan !== false
              };
              const scanRes = isDiff
                ? scanDiff({ diffText: text, filePath: targetPath, options: gateOptions })
                : scanFileContent({ content: text, filePath: targetPath, options: gateOptions });

              if (scanRes.findings.length > 0) {
                const hits = scanRes.findings.map(f => ({
                  type: f.category,
                  label: f.ruleId,
                  match: f.evidence,
                  explanation: f.explanation,
                  remediation: f.remediation,
                  line: f.line
                }));
                setLastAudit({
                  level: scanRes.action === 'block' ? 'red' : 'yellow',
                  hits,
                  diffGate: { action: scanRes.action, stats: scanRes.stats, findings: scanRes.findings },
                  at: Date.now(),
                  source: 'guard:diff_gate'
                });

                const hasCritical = scanRes.findings.some(f => isCriticalThreat(f));
                const forceBlock = cfg.secretBlockCritical !== false && hasCritical;

                if (scanRes.action === 'block' || forceBlock) {
                  const top = scanRes.findings[0];
                  if (cfg.enableAuditLog) {
                    recordGuardHit(recorder, {
                      sessionId, callId: execution.callId, toolName: name, args,
                      success: false,
                      blocked: `DiffGate [${top.ruleId}]: ${top.explanation}` + (forceBlock ? ' [CRITICAL-FORCED]' : ''),
                      score: 95, tags: [top.category],
                      reason: `Blocked by security diff gate: [${top.ruleId}] ${top.explanation}`
                    });
                  }
                  return '\u26d4 [shadow-auditor] Code-security gate BLOCKED diff (' + top.ruleId + '): ' + top.explanation + '. Remediation: ' + top.remediation;
                }
              }
            }
          }
        } catch (err) { logger.warn?.('[shadow-auditor] Guard execution error:', err); }
        return undefined;
      });
      return () => { try { off && off(); } catch (err) { logger.debug?.('[shadow-auditor] Guard cleanup failed (error type: ' + (err?.name || 'Error') + ').'); } };
    }, 'shadow-auditor: mandatory guard');
  } catch (err) {
    logger.debug?.('[shadow-auditor] Mandatory guard registration failed (error type: ' + (err?.name || 'Error') + ').');
  }
}

/**
 * Registers multi-surface lifecycle hooks on Cordis context with prepend priority (#108, #109, #110, #111, #124, #125, #126, #135).
 */
export function registerLifecycleHooks(ctx, { getConfig, recorder, isCommandTool, isFileReadTool, isFileWriteTool, recordGuardHit, setLastAudit, logger, stripperRegistry }) {
  registerToolsGuard(ctx, { getConfig, recorder, isCommandTool, isFileReadTool, isFileWriteTool, recordGuardHit, setLastAudit, logger });
  if (!ctx || typeof ctx.on !== 'function') return;

  // 1. Pre-filter incoming user prompts on agent/pre-step (#109, #110, #125, #126)
  try {
    ctx.effect(() => {
      const off = ctx.on('agent/pre-step', async ({ agent, messages, turn, signal }, next) => {
        try {
          const cfg = getConfig();
          const sessionId = String(agent?.session?.header?.id ?? 'unknown');
          if (cfg.enablePromptInjectionScan !== false && Array.isArray(messages) && messages.length > 0) {
            const findings = scanPromptMessages(messages);
            if (findings.length > 0) {
              const top = findings[0];
              setLastAudit({
                level: 'red',
                hits: findings.map(f => ({ type: f.category, label: f.ruleId, match: f.evidence })),
                at: Date.now(),
                source: 'agent:pre-step'
              });
              if (cfg.enableAuditLog) {
                recordGuardHit(recorder, {
                  sessionId, callId: `turn-${turn}`, toolName: 'agent/pre-step',
                  args: { turn, excerpt: top.evidence },
                  success: false,
                  blocked: `Prompt Injection [${top.ruleId}]: ${top.explanation}`,
                  score: 95, tags: ['prompt-injection', 'adversarial'],
                  reason: `Blocked adversarial prompt injection: [${top.ruleId}] ${top.explanation}`
                });
              }
              return { kind: 'reject' };
            }
          }

          if (cfg.enableReversibleMasking !== false && stripperRegistry && Array.isArray(messages)) {
            const stripper = stripperRegistry.getStripper(sessionId);
            messages = stripMessages(messages, stripper);
          }
        } catch (err) {
          logger.warn?.('[shadow-auditor] agent/pre-step inspection error:', err);
        }
        return typeof next === 'function' ? next() : { kind: 'enter', messages };
      }, { prepend: true });
      return () => { try { off?.(); } catch (_) {} };
    }, 'shadow-auditor: agent/pre-step prompt guard');
  } catch (err) {
    logger.debug?.('[shadow-auditor] agent/pre-step listener registration failed: ' + (err?.name || 'Error'));
  }

  // 2. PreToolUse waterfall: tools/pre-execute with ask approval integration (#108, #109, #125)
  try {
    ctx.effect(() => {
      const off = ctx.on('tools/pre-execute', async (exec, next) => {
        try {
          const cfg = getConfig();
          const name = String(exec.name || '');
          const args = exec.arguments;
          if (isCommandTool(name) && cfg.blockDangerousCommands) {
            const cmd = typeof args === 'object' && args !== null
              ? String(args.command || args.cmd || args.CommandLine || '')
              : String(args || '');
            if (cmd.trim()) {
              const cwd = (typeof args === 'object' && args !== null ? (args.cwd || args.Cwd) : null)
                || exec.agent?.session?.header?.cwd
                || process.cwd();
              const hit = findDangerous(cmd, {
                customBlockedCommands: cfg.customBlockedCommands,
                sensitivePathPatterns: cfg.sensitivePathPatterns,
                workspace: cwd,
                logger,
              });
              if (hit) {
                const isCritical = isCriticalThreat(hit);
                const forceBlock = cfg.secretBlockCritical !== false && isCritical;
                if (!forceBlock && cfg.shellGuardMode === 'ask') {
                  return {
                    kind: 'ask',
                    reason: `[shadow-auditor] Confirmation required: ${hit.label}`,
                    displayReason: {
                      en: `[shadow-auditor] Elevated risk: ${hit.label} (\`${String(hit.match).slice(0, 100)}\`)`
                    }
                  };
                }
                if (forceBlock || cfg.shellGuardMode === 'enforce') {
                  return {
                    kind: 'deny',
                    reason: `[shadow-auditor] Command blocked: ${hit.label}`
                  };
                }
              }
            }
          }
        } catch (err) {
          logger.warn?.('[shadow-auditor] tools/pre-execute evaluation error:', err);
        }
        return typeof next === 'function' ? next() : { kind: 'allow' };
      }, { prepend: true });
      return () => { try { off?.(); } catch (_) {} };
    }, 'shadow-auditor: tools/pre-execute approval waterfall');
  } catch (err) {
    logger.debug?.('[shadow-auditor] tools/pre-execute hook registration failed: ' + (err?.name || 'Error'));
  }

  // 3. PostToolUse output sanitization: tools/post-execute (#109, #111, #125, #135)
  try {
    ctx.effect(() => {
      const off = ctx.on('tools/post-execute', async (exec, result, next) => {
        const decision = typeof next === 'function' ? await next() : { kind: 'accept' };
        try {
          const cfg = getConfig();
          if (cfg.strictSecretScanning !== false && result) {
            const content = decision.content ?? result.content;
            if (Array.isArray(content)) {
              const sanitized = sanitizeResultBlocks(content);
              const hasLeak = JSON.stringify(sanitized) !== JSON.stringify(content);
              if (hasLeak) {
                const sid = String(exec.agent?.session?.header?.id ?? 'unknown');
                const stripper = (cfg.enableReversibleMasking !== false && stripperRegistry)
                  ? stripperRegistry.getStripper(sid)
                  : null;
                if (cfg.enableAuditLog) {
                  recordGuardHit(recorder, {
                    sessionId: sid, callId: exec.callId, toolName: exec.name,
                    args: exec.arguments, success: true,
                    score: 75, tags: ['secrets', 'post-execute-sanitization'],
                    reason: `Masked raw secret leaked in tool execution output (${exec.name})`,
                    stripper
                  });
                }
                return { ...decision, kind: 'accept', content: sanitized };
              }
            }
          }
        } catch (err) {
          logger.warn?.('[shadow-auditor] tools/post-execute sanitization error:', err);
        }
        return decision;
      }, { prepend: true });
      return () => { try { off?.(); } catch (_) {} };
    }, 'shadow-auditor: tools/post-execute secret sanitizer');
  } catch (err) {
    logger.debug?.('[shadow-auditor] tools/post-execute hook registration failed: ' + (err?.name || 'Error'));
  }
}
