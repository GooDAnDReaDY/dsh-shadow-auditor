/**
 * @file two-phase.js
 * Two-phase scanner architecture (fast Aho-Corasick filter + precise regex) (#102).
 * Prevents expensive regex evaluation on 99% of clean inputs.
 */

import { AhoCorasick } from '../ac.js';

export class TwoPhaseScanner {
  /**
   * @param {Array<{ id: string, name?: string, needles?: string[], regex?: RegExp, test?: Function }>} rules
   * @param {object} [options]
   * @param {boolean} [options.caseSensitive=false]
   */
  constructor(rules = [], options = {}) {
    this.caseSensitive = options.caseSensitive ?? false;
    this.rules = [];
    this.fallbackRules = [];
    this.needleToRuleMap = new Map();
    this.automaton = new AhoCorasick([], { caseSensitive: this.caseSensitive });

    if (Array.isArray(rules) && rules.length > 0) {
      this.setRules(rules);
    }
  }

  /**
   * Configures scanner rules and compiles the Aho-Corasick needle filter.
   * @param {Array<object>} rules
   */
  setRules(rules) {
    this.rules = rules;
    this.fallbackRules = [];
    this.needleToRuleMap.clear();

    const allNeedles = [];

    for (const rule of rules) {
      const needles = Array.isArray(rule.needles) ? rule.needles.filter(n => typeof n === 'string' && n.length > 0) : [];
      if (needles.length === 0) {
        this.fallbackRules.push(rule);
      } else {
        for (const needle of needles) {
          const key = this.caseSensitive ? needle : needle.toLowerCase();
          if (!this.needleToRuleMap.has(key)) {
            this.needleToRuleMap.set(key, new Set());
            allNeedles.push(needle);
          }
          this.needleToRuleMap.get(key).add(rule);
        }
      }
    }

    this.automaton.build(allNeedles);
  }

  /**
   * Performs two-phase scan:
   * Phase 1: Fast linear O(N) needle search using Aho-Corasick.
   * Phase 2: Precise regex evaluations ONLY for candidate rules.
   *
   * @param {string} text
   * @returns {{ matches: Array<object>, stats: { totalRules: number, candidateRules: number, regexEvaluations: number, skippedRules: number } }}
   */
  scan(text) {
    const totalRules = this.rules.length;
    if (typeof text !== 'string' || text.length === 0 || totalRules === 0) {
      return {
        matches: [],
        stats: { totalRules, candidateRules: 0, regexEvaluations: 0, skippedRules: totalRules }
      };
    }

    // Phase 1: Fast AC needle scan
    const candidateRuleSet = new Set(this.fallbackRules);
    const needleHits = this.automaton.search(text);

    for (const hit of needleHits) {
      const key = this.caseSensitive ? hit.pattern : hit.pattern.toLowerCase();
      const matchedRules = this.needleToRuleMap.get(key);
      if (matchedRules) {
        for (const r of matchedRules) {
          candidateRuleSet.add(r);
        }
      }
    }

    const candidateRules = candidateRuleSet.size;
    let regexEvaluations = 0;
    const matches = [];

    // Phase 2: Targeted regex evaluation
    for (const rule of candidateRuleSet) {
      if (!rule.regex && typeof rule.test !== 'function') continue;
      regexEvaluations++;

      if (rule.regex) {
        rule.regex.lastIndex = 0;
        let m;
        while ((m = rule.regex.exec(text)) !== null) {
          const raw = m[1] || m[0];
          matches.push({
            ruleId: rule.id || rule.name,
            ruleName: rule.name || rule.id,
            match: raw,
            index: m.index,
            length: raw.length
          });
          if (m[0].length === 0) rule.regex.lastIndex++;
          if (!rule.regex.global) break;
        }
      } else if (typeof rule.test === 'function') {
        const res = rule.test(text);
        if (res) {
          matches.push({
            ruleId: rule.id || rule.name,
            ruleName: rule.name || rule.id,
            result: res
          });
        }
      }
    }

    return {
      matches,
      stats: {
        totalRules,
        candidateRules,
        regexEvaluations,
        skippedRules: totalRules - candidateRules
      }
    };
  }

  /**
   * Helper benchmarking two-phase speed vs naive full regex scanning.
   * @param {string[]} cleanInputs
   * @param {string[]} dirtyInputs
   */
  benchmark(cleanInputs = [], dirtyInputs = []) {
    const allInputs = [...cleanInputs, ...dirtyInputs];
    let twoPhaseRegexCalls = 0;

    const start2P = performance.now();
    for (const input of allInputs) {
      const res = this.scan(input);
      twoPhaseRegexCalls += res.stats.regexEvaluations;
    }
    const duration2P = performance.now() - start2P;

    // Naive evaluation count
    const naiveRegexCalls = allInputs.length * this.rules.length;

    return {
      totalInputs: allInputs.length,
      twoPhaseRegexCalls,
      naiveRegexCalls,
      skippedPercentage: naiveRegexCalls > 0 ? ((naiveRegexCalls - twoPhaseRegexCalls) / naiveRegexCalls) * 100 : 100,
      durationMs: duration2P
    };
  }
}

export function createTwoPhaseScanner(rules, options) {
  return new TwoPhaseScanner(rules, options);
}
