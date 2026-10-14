/**
 * @file mask.js
 * Reversible masking module for LLM prompt shielding (#147).
 * Replaces sensitive values with structured placeholders (<TYPE_N>)
 * and allows exact restoration of cleartext responses without disk leakage.
 */

export {
  Stripper,
  testMasking,
  stripInto,
  summarizeMapping,
  loadMapping
} from './mask/engine.js';

export {
  StripperRegistry,
  InMemoryStorageAdapter,
  DomainStorageAdapter,
  createStorageAdapter
} from './mask/store.js';
