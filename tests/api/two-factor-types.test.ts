/**
 * Type-level checks of the 2FA answers against the server's responses. `expectTypeOf` does
 * nothing at run time; these fail under `tsc` only.
 */
import { describe, expectTypeOf, test } from 'vitest';
import type {
  TwoFactorChallengeResponse,
  TwoFactorDisableResponse,
  TwoFactorEnrollmentResponse,
  TwoFactorStatusResponse,
} from '../../lib/index';

// REGRESSION: 2FA types describe what the server sends
describe('2FA answer types', () => {
  test('status has no policy', () => {
    expectTypeOf<TwoFactorStatusResponse>().not.toHaveProperty('policy');
  });

  test('disable answers { disabled: true }', () => {
    expectTypeOf<TwoFactorDisableResponse>().toEqualTypeOf<{ disabled: true }>();
  });

  test('enrolment and challenge answers carry the TOTP digit count', () => {
    expectTypeOf<TwoFactorEnrollmentResponse>().toHaveProperty('totp_digits');
    expectTypeOf<TwoFactorChallengeResponse>().toHaveProperty('totp_digits');
  });
});
