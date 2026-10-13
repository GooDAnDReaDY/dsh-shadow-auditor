const SHELL_VERBS = /\b(?:rm|del|rd|unlink|rmdir|remove-item)\b/i;
const FORCE_FLAGS = /(?:^|\s)-(?:[a-z]*[rf][a-z]*|\/[sqf])(?:\s|$)/i;
const NETWORK_TOOLS = /\b(?:curl|wget|nc|ncat|socat|scp|rsync|ssh|ftp|sftp|telnet)\b/i;
const REMOTE_PKG_EXEC = /\b(?:npx|bunx|pnpm\s+dlx|yarn\s+dlx|npm\s+exec)\b/i;
const DEP_INSTALL = /\b(?:npm|pnpm|yarn|bun|pip|pip3|uv|poetry)\s+(?:install|add|i\b|ci|update|up)\b/i;
const HEAVY_BUILD = /\b(?:make|cmake|ninja|cargo\s+build|go\s+build|tsc\b|vite\s+build|next\s+build)\b/i;

const WINDOW_MS = 10 * 60_000;
const SAME_TAG_THRESHOLD = 3;
const SAME_TAG_BONUS = 15;
const CONSECUTIVE_HIGH_BONUS = 10;
const HIGH_RISK_FLOOR = 60;

/**
 * Standard severity weights for calculating weighted security score (#97).
 */
export const SEVERITY_WEIGHT = {
  critical: 1.0,
  high: 0.8,
  medium: 0.5,
  low: 0.2
};

/**
 * Calculates a normalized session Security Score (0 to 100) and status rating (#97).
 * Status ratings:
 * - >= 85: "Safe" (green)
 * - 60 - 84: "Needs Attention" (yellow)
 * - < 60: "Dangerous" (red)
 * @param {object} counts Or records
 * @returns {{ score: number, rating: string, status: string, penalty: number }}
 */
export function calculateSecurityScore(input = {}) {
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;

  if (Array.isArray(input)) {
    for (const item of input) {
      const sev = (item.severity || item.riskLevel || '').toLowerCase();
      if (sev === 'critical') critical++;
      else if (sev === 'high') high++;
      else if (sev === 'medium') medium++;
      else if (sev === 'low') low++;
      else if (typeof item.score === 'number') {
        if (item.score >= 80) high++;
        else if (item.score >= 40) medium++;
        else low++;
      }
    }
  } else if (typeof input === 'object' && input !== null) {
    if (input.riskLevels) {
      high += input.riskLevels.high || 0;
      medium += input.riskLevels.medium || 0;
      low += input.riskLevels.low || 0;
    }
    critical += input.critical || 0;
    high += input.high || 0;
    medium += input.medium || 0;
    low += input.low || 0;
  }

  // Penalty calculation: critical has heavy impact, capped at 100
  const totalPenalty = (critical * 25 * SEVERITY_WEIGHT.critical) +
    (high * 15 * SEVERITY_WEIGHT.high) +
    (medium * 6 * SEVERITY_WEIGHT.medium) +
    (low * 2 * SEVERITY_WEIGHT.low);

  const score = Math.max(0, Math.min(100, Math.round(100 - totalPenalty)));

  let rating = 'Safe';
  let status = 'safe';

  if (score < 60 || critical > 0) {
    rating = 'Dangerous';
    status = 'dangerous';
  } else if (score < 85 || high > 0) {
    rating = 'Needs Attention';
    status = 'needs_attention';
  }

  return {
    score,
    rating,
    status,
    penalty: Math.round(totalPenalty)
  };
}

export function evaluateRisk(toolName, args) {
  let text = "";
  if (typeof args === "string") text = args;
  else if (args && typeof args === "object") {
    if (typeof args.command === "string") text = args.command;
    else text = JSON.stringify(args);
  }

  const tags = [];
  const reasons = [];
  let score = 5;

  const add = (tag, points, reason) => {
    if (!tags.includes(tag)) {
      tags.push(tag);
      score += points;
      reasons.push(reason);
    }
  };

  const lower = text.toLowerCase();

  // Credential reading/mentioning (handles .env without boundary failure)
  if (/(?:\.env|passwd|id_rsa|id_ed25519|credentials|secret|api[_-]?key)/i.test(lower)) {
    add("credential-read", 65, "Credential or private key file access detected");
  }

  // Destructive shell operations
  if (SHELL_VERBS.test(text) && (FORCE_FLAGS.test(text) || /\b(?:del|rd)\b/i.test(text))) {
    add("destructive", 55, "Destructive file or directory deletion");
  }

  // Network egress
  if (NETWORK_TOOLS.test(text)) {
    add("network-egress", 40, "Outbound network command");
  }

  // Sudo or elevated permissions
  if (/\bsudo\b/i.test(text)) {
    add("sudo", 55, "Privilege escalation via sudo");
  }
  if (/chmod\s+(?:777|a\+w)/i.test(text)) {
    add("outside-workspace", 55, "Insecure file permissions assignment (chmod 777)");
  }

  // Remote package execution on the fly
  if (REMOTE_PKG_EXEC.test(text)) {
    add("expensive", 45, "Remote package on-the-fly execution (npx/dlx)");
  }

  // Dependency installations
  if (DEP_INSTALL.test(text)) {
    add("dependency-install", 25, "Package dependency installation");
  }

  // Heavy build tasks
  if (HEAVY_BUILD.test(text)) {
    add("heavy-build", 20, "Heavy build or compilation process");
  }

  if (tags.length === 0) {
    tags.push("benign");
    reasons.push("Routine operation");
  }

  let riskLevel = "low";
  if (tags.includes("destructive") || tags.includes("credential-read") || tags.includes("outside-workspace") || score >= 80) {
    riskLevel = "high";
  } else if (tags.includes("sudo") || tags.includes("network-egress") || tags.includes("expensive") || score >= 40) {
    riskLevel = "medium";
  }
  return { tags, score: Math.min(100, score), riskLevel, reasons };
}

export function applyCumulative(
  base,
  tags,
  recent = [],
  now = Date.now(),
  windowMs = WINDOW_MS,
  highRiskFloor = HIGH_RISK_FLOOR
) {
  let score = base;
  const extraReasons = [];
  const inWindow = recent.filter(event => now - event.time <= windowMs);

  for (const tag of tags) {
    if (tag === "benign") continue;
    const count = inWindow.filter(event => event.tags && event.tags.includes(tag)).length;
    if (count >= SAME_TAG_THRESHOLD) {
      score += SAME_TAG_BONUS;
      extraReasons.push(`Tag ${tag} repeated frequently in 10 minutes (+${SAME_TAG_BONUS})`);
      break;
    }
  }

  const last = recent[recent.length - 1];
  if (last && base >= highRiskFloor && last.score >= highRiskFloor) {
    score += CONSECUTIVE_HIGH_BONUS;
    extraReasons.push(`Consecutive high-risk invocation (+${CONSECUTIVE_HIGH_BONUS})`);
  }

  return { score: Math.min(100, score), extraReasons };
}
