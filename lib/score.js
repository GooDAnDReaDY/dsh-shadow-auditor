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

export function evaluateRisk(toolName, args) {
  let text = '';
  if (typeof args === 'string') text = args;
  else if (args && typeof args === 'object') {
    if (typeof args.command === 'string') text = args.command;
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
    add('credential-read', 65, 'Обращение к файлу ключей/паролей');
  }

  // Destructive shell operations
  if (SHELL_VERBS.test(text) && (FORCE_FLAGS.test(text) || /\b(?:del|rd)\b/i.test(text))) {
    add('destructive', 55, 'Деструктивное удаление файлов/директорий');
  }

  // Network egress
  if (NETWORK_TOOLS.test(text)) {
    add('network-egress', 40, 'Команда сетевого взаимодействия');
  }

  // Sudo or elevated permissions
  if (/\bsudo\b/i.test(text)) {
    add('sudo', 55, 'Повышение привилегий через sudo');
  }
  if (/chmod\s+(?:777|a\+w)/i.test(text)) {
    add('outside-workspace', 55, 'Установка небезопасных прав доступа (chmod 777)');
  }

  // Remote package execution on the fly
  if (REMOTE_PKG_EXEC.test(text)) {
    add('expensive', 45, 'Выполнение удалённого пакета на лету (npx/dlx)');
  }

  // Dependency installations
  if (DEP_INSTALL.test(text)) {
    add('dependency-install', 25, 'Установка зависимостей пакетов');
  }

  // Heavy build tasks
  if (HEAVY_BUILD.test(text)) {
    add('heavy-build', 20, 'Тяжёлая задача сборки/компиляции');
  }

  if (tags.length === 0) {
    tags.push('benign');
    reasons.push('Штатная операция');
  }

  return { tags, score: Math.min(100, score), reasons };
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
    if (tag === 'benign') continue;
    const count = inWindow.filter(event => event.tags && event.tags.includes(tag)).length;
    if (count >= SAME_TAG_THRESHOLD) {
      score += SAME_TAG_BONUS;
      extraReasons.push(`Тег ${tag} часто повторяется за 10 минут (+${SAME_TAG_BONUS})`);
      break;
    }
  }

  const last = recent[recent.length - 1];
  if (last && base >= highRiskFloor && last.score >= highRiskFloor) {
    score += CONSECUTIVE_HIGH_BONUS;
    extraReasons.push(`Повторный вызов с высоким риском (+${CONSECUTIVE_HIGH_BONUS})`);
  }

  return { score: Math.min(100, score), extraReasons };
}