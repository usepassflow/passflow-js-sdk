import { describe, expect, test } from 'vitest';
import { normalizeRecoveryCode } from '../../lib/utils/validation';

// REGRESSION: recovery codes follow the server format, XXXX-XXXX-XXXX by default and at least 10 characters
describe('normalizeRecoveryCode', () => {
  test('upper-cases a lower-case code and keeps its dashes', () => {
    expect(normalizeRecoveryCode('abcd-efgh-jkmn')).toBe('ABCD-EFGH-JKMN');
  });

  test('accepts a 12-character code without dashes', () => {
    expect(normalizeRecoveryCode('ABCDEFGHJKMN')).toBe('ABCDEFGHJKMN');
  });

  test('accepts a 16-character code with dashes', () => {
    expect(normalizeRecoveryCode('ABCD-EFGH-JKMN-PQRS')).toBe('ABCD-EFGH-JKMN-PQRS');
  });

  test('refuses a code with fewer than 10 characters once the dashes are gone', () => {
    expect(normalizeRecoveryCode('ABCD-1234')).toBeNull();
  });

  test('refuses an empty code', () => {
    expect(normalizeRecoveryCode('')).toBeNull();
  });
});
