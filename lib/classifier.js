/**
 * @file classifier.js
 * Optional asynchronous LLM-assisted command classification (#85).
 * Invokes local Ollama or compatible inference API to disambiguate borderline commands.
 */

export const CLASSIFIER_DEFAULTS = {
  endpoint: 'http://127.0.0.1:11434/api/generate',
  model: 'llama3',
  timeoutMs: 2500,
  borderlineMinScore: 40,
  borderlineMaxScore: 80
};

/**
 * Checks whether a command threat score falls within the ambiguous borderline zone.
 * @param {number} score
 * @returns {boolean}
 */
export function isBorderlineScore(score) {
  return typeof score === 'number' && score >= CLASSIFIER_DEFAULTS.borderlineMinScore && score <= CLASSIFIER_DEFAULTS.borderlineMaxScore;
}

/**
 * Asynchronously classifies a suspicious command via local LLM (#85).
 * Safe failback: network or model errors never throw or block execution.
 * @param {object} options
 * @param {string} options.command
 * @param {string} [options.endpoint]
 * @param {string} [options.model]
 * @param {number} [options.timeoutMs]
 * @param {Function} [options.fetchFn]
 * @returns {Promise<object>}
 */
export async function classifyCommand(options = {}) {
  const {
    command = '',
    endpoint = CLASSIFIER_DEFAULTS.endpoint,
    model = CLASSIFIER_DEFAULTS.model,
    timeoutMs = CLASSIFIER_DEFAULTS.timeoutMs,
    fetchFn = globalThis.fetch
  } = options;

  if (!command || typeof command !== 'string') {
    return {
      classifierUsed: false,
      dangerous: false,
      confidence: 0,
      reasoning: 'Empty command string'
    };
  }

  const prompt = [
    'You are a security command classifier.',
    'Classify the following shell command as DANGEROUS or SAFE.',
    'Command:',
    command,
    'Respond strictly in JSON format with fields: {"dangerous": boolean, "confidence": number, "reasoning": string}'
  ].join('\n');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetchFn(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, prompt, stream: false, format: 'json' }),
      signal: controller.signal
    });

    clearTimeout(timer);

    if (!res.ok) {
      return {
        classifierUsed: true,
        dangerous: false,
        confidence: 0,
        reasoning: `Classifier HTTP error ${res.status}: ${res.statusText}`,
        fallback: true
      };
    }

    const data = await res.json();
    const rawResponse = data.response || data.message?.content || '{}';
    let parsed = {};
    try {
      parsed = JSON.parse(rawResponse);
    } catch {
      const isDangerous = /dangerous|threat|destructive/i.test(rawResponse);
      parsed = { dangerous: isDangerous, confidence: 0.5, reasoning: rawResponse.slice(0, 100) };
    }

    return {
      classifierUsed: true,
      dangerous: Boolean(parsed.dangerous),
      confidence: Number(parsed.confidence) || 0.7,
      reasoning: String(parsed.reasoning || 'Evaluated by local model'),
      fallback: false
    };
  } catch (err) {
    clearTimeout(timer);
    return {
      classifierUsed: true,
      dangerous: false,
      confidence: 0,
      reasoning: `Fail-safe fallback: ${err?.message || 'timeout/connection error'}`,
      fallback: true
    };
  }
}