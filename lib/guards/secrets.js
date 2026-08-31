export const SECRET_PATTERNS = [
  { id: 'openai', label: 'OpenAI key', regex: /sk-(?:proj-)?[A-Za-z0-9]{20,}/g },
  { id: 'anthropic', label: 'Anthropic key', regex: /sk-ant-[A-Za-z0-9\-_]{20,}/g },
  { id: 'github-ghp', label: 'GitHub PAT', regex: /ghp_[A-Za-z0-9]{20,}/g },
  { id: 'github-gho', label: 'GitHub OAuth', regex: /gho_[A-Za-z0-9]{20,}/g },
  { id: 'github-pat', label: 'GitHub fine-grained', regex: /github_pat_[A-Za-z0-9_]{20,}/g },
  { id: 'aws', label: 'AWS access key', regex: /AKIA[0-9A-Z]{16}/g },
  { id: 'jwt', label: 'JWT', regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-.\/=]{10,}/g },
  { id: 'private-key', label: 'Private key', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
];

export const INFRA_PATTERNS = [
  { id: 'home-path', label: 'Home path', regex: /\/home\/[A-Za-z0-9_\-\.]+/g },
  { id: 'mnt-path', label: 'MNT path', regex: /\/mnt\/\S+/g },
  { id: 'opt-path', label: 'OPT path', regex: /\/opt\/\S+/g },
  { id: 'private-ip', label: 'Private IP', regex: /\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g },
];

const ALLOWLIST = [
  /AKIAIOSFODNN7EXAMPLE/,
  /example/i,
  /sk-test/i,
];

function isAllowlisted(match) {
  return ALLOWLIST.some((re) => re.test(match));
}

export function scanSecrets(text) {
  if (typeof text !== 'string' || text.length === 0) return { level: 'green', hits: [] };
  const hits = [];

  for (const p of SECRET_PATTERNS) {
    p.regex.lastIndex = 0;
    let m;
    while ((m = p.regex.exec(text)) !== null) {
      const val = m[0];
      if (isAllowlisted(val)) continue;
      // avoid infinite loop on zero-length
      if (val.length === 0) p.regex.lastIndex++;
      hits.push({ type: p.id, label: p.label, match: val.slice(0, 80), index: m.index });
      // prevent duplicate same index
      if (hits.length > 50) break;
    }
  }
  if (hits.length > 0) return { level: 'red', hits };

  for (const p of INFRA_PATTERNS) {
    p.regex.lastIndex = 0;
    let m;
    while ((m = p.regex.exec(text)) !== null) {
      const val = m[0];
      if (isAllowlisted(val)) continue;
      if (val.length === 0) p.regex.lastIndex++;
      hits.push({ type: p.id, label: p.label, match: val.slice(0, 80), index: m.index });
      if (hits.length > 20) break;
    }
  }
  if (hits.length > 0) return { level: 'yellow', hits };
  return { level: 'green', hits: [] };
}
