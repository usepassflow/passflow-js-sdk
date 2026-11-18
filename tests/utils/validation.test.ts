import { describe, expect, test } from 'vitest';
import { normalizeRecoveryCode } from '../../lib/utils/validation';

// REGRESSION: codes are issued as XXXX-XXXX-XXXX, but older 8-character codes stay valid: the server decides
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

  test('accepts an older 8-character XXXX-XXXX code: the server still matches it', () => {
    expect(normalizeRecoveryCode('abcd-1234')).toBe('ABCD-1234');
  });

  test('refuses a code of dashes only', () => {
    expect(normalizeRecoveryCode('--')).toBeNull();
  });

  test('refuses a code with characters outside letters, digits and dashes', () => {
    expect(normalizeRecoveryCode('ABCD_1234')).toBeNull();
  });

  test('refuses a code longer than 64 characters', () => {
    expect(normalizeRecoveryCode('A'.repeat(65))).toBeNull();
  });

  test('refuses an empty code', () => {
    expect(normalizeRecoveryCode('')).toBeNull();
  });
});
