/**
 * @file ac.js
 * Pure JavaScript Aho-Corasick string matching automaton (#101).
 * Builds a Trie with BFS failure transitions to locate multiple string needles in O(N + M) time.
 */

export class AhoCorasick {
  /**
   * @param {string[]} [patterns]
   * @param {object} [options]
   * @param {boolean} [options.caseSensitive=true]
   */
  constructor(patterns = [], options = {}) {
    this.caseSensitive = options.caseSensitive ?? true;
    this.trie = [{ next: new Map(), fail: 0, outputs: [] }];
    this.patterns = [];
    if (Array.isArray(patterns) && patterns.length > 0) {
      this.build(patterns);
    }
  }

  /**
   * Builds the Aho-Corasick automaton trie and failure transitions.
   * @param {string[]} patterns
   */
  build(patterns) {
    this.trie = [{ next: new Map(), fail: 0, outputs: [] }];
    this.patterns = patterns;

    // 1. Build Trie root and branches
    for (let i = 0; i < patterns.length; i++) {
      const orig = patterns[i];
      if (typeof orig !== 'string' || orig.length === 0) continue;
      const pat = this.caseSensitive ? orig : orig.toLowerCase();

      let curr = 0;
      for (let j = 0; j < pat.length; j++) {
        const ch = pat[j];
        if (!this.trie[curr].next.has(ch)) {
          const nextIdx = this.trie.length;
          this.trie.push({ next: new Map(), fail: 0, outputs: [] });
          this.trie[curr].next.set(ch, nextIdx);
        }
        curr = this.trie[curr].next.get(ch);
      }
      this.trie[curr].outputs.push({
        pattern: orig,
        length: pat.length,
        patternIndex: i
      });
    }

    // 2. Build failure links using BFS
    const queue = [];
    for (const [, nextIdx] of this.trie[0].next) {
      this.trie[nextIdx].fail = 0;
      queue.push(nextIdx);
    }

    while (queue.length > 0) {
      const curr = queue.shift();
      const currFail = this.trie[curr].fail;

      for (const [ch, nextIdx] of this.trie[curr].next) {
        let f = currFail;
        while (f > 0 && !this.trie[f].next.has(ch)) {
          f = this.trie[f].fail;
        }
        const failTarget = this.trie[f].next.has(ch) ? this.trie[f].next.get(ch) : 0;
        this.trie[nextIdx].fail = failTarget;

        if (this.trie[failTarget].outputs.length > 0) {
          this.trie[nextIdx].outputs.push(...this.trie[failTarget].outputs);
        }
        queue.push(nextIdx);
      }
    }
  }

  /**
   * Searches for all pattern matches in text in a single linear pass.
   * @param {string} text
   * @returns {Array<{ pattern: string, index: number, length: number, patternIndex: number }>}
   */
  search(text) {
    if (typeof text !== 'string' || text.length === 0 || this.trie.length <= 1) {
      return [];
    }

    const target = this.caseSensitive ? text : text.toLowerCase();
    const matches = [];
    let curr = 0;

    for (let i = 0; i < target.length; i++) {
      const ch = target[i];
      while (curr > 0 && !this.trie[curr].next.has(ch)) {
        curr = this.trie[curr].fail;
      }

      if (this.trie[curr].next.has(ch)) {
        curr = this.trie[curr].next.get(ch);
      } else {
        curr = 0;
      }

      if (this.trie[curr].outputs.length > 0) {
        for (const out of this.trie[curr].outputs) {
          matches.push({
            pattern: out.pattern,
            index: i - out.length + 1,
            length: out.length,
            patternIndex: out.patternIndex
          });
        }
      }
    }

    return matches;
  }

  /**
   * Fast boolean test whether any registered pattern appears in text.
   * @param {string} text
   * @returns {boolean}
   */
  hasMatch(text) {
    if (typeof text !== 'string' || text.length === 0 || this.trie.length <= 1) {
      return false;
    }

    const target = this.caseSensitive ? text : text.toLowerCase();
    let curr = 0;

    for (let i = 0; i < target.length; i++) {
      const ch = target[i];
      while (curr > 0 && !this.trie[curr].next.has(ch)) {
        curr = this.trie[curr].fail;
      }
      if (this.trie[curr].next.has(ch)) {
        curr = this.trie[curr].next.get(ch);
      } else {
        curr = 0;
      }
      if (this.trie[curr].outputs.length > 0) {
        return true;
      }
    }

    return false;
  }
}
