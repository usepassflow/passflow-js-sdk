/**
 * Type-level checks of the 2FA answers against the server's responses. `expectTypeOf` does
 * nothing at run time; these fail under `tsc` only.
 */
import { describe, expectTypeOf, test } from 'vitest';
import type {
  TwoFactorChallengeResponse,
  TwoFactorConfirmResponse,
  TwoFactorDisableResponse,
  TwoFactorEnrollmentResponse,
  TwoFactorStatusResponse,
  TwoFactorVerifyResponse,
  TwoFactorVerifyResponseV2,
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

  test('a second factor under an OIDC parent answers with the redirect, or a form post', () => {
    expectTypeOf<TwoFactorVerifyResponseV2['redirect_url']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<TwoFactorVerifyResponseV2['form_post']>().toEqualTypeOf<
      { action: string; fields: Record<string, string> } | undefined
    >();
    expectTypeOf<TwoFactorVerifyResponse['redirect_url']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<TwoFactorVerifyResponse['form_post']>().toEqualTypeOf<
      { action: string; fields: Record<string, string> } | undefined
    >();
  });

  test('enrolment and challenge answers say whether this device can be trusted', () => {
    expectTypeOf<TwoFactorEnrollmentResponse['device_trust_available']>().toEqualTypeOf<boolean>();
    expectTypeOf<TwoFactorChallengeResponse['device_trust_available']>().toEqualTypeOf<boolean>();
  });

  test('confirm carries no recovery codes when the app does not use them', () => {
    expectTypeOf<TwoFactorConfirmResponse['recovery_codes']>().toEqualTypeOf<string[] | undefined>();
  });
});
