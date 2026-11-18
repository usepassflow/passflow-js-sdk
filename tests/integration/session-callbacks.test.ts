/**
 * `passflow.session({ createSession })` runs once for every way a sign-in completes, also when
 * `session()` was called after the instance was built (the usual case). Only the HTTP layer and
 * the platform's passkey ceremony are stubbed.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AppAPI, AuthAPI } from '../../lib/api';
import { TwoFactorApiClient } from '../../lib/api/two-factor';
import { Passflow } from '../../lib/passflow';
import { TEST_CONFIG, VALID_TOKENS } from '../helpers/fixtures';
import { createMockPlatform } from '../helpers/mock-platform';

const PENDING = { tfa_token: 'tfa.jwt.token', challenge_id: 'c-1' };
const CREDENTIALS = { email: 'a@example.com', password: 'pw' };

describe('createSession runs once per completed sign-in', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.spyOn(AppAPI.prototype, 'getAppSettings').mockResolvedValue({ pkce_enabled: false } as never);
    vi.spyOn(AuthAPI.prototype, 'signUp').mockResolvedValue({ ...VALID_TOKENS } as never);
    vi.spyOn(AuthAPI.prototype, 'passkeyRegisterStart').mockResolvedValue({
      challenge_id: 'pk-1',
      publicKey: { user: { id: 'user-1' } },
    } as never);
    vi.spyOn(AuthAPI.prototype, 'passkeyRegisterComplete').mockResolvedValue({ ...VALID_TOKENS } as never);
    vi.spyOn(TwoFactorApiClient.prototype, 'verify').mockResolvedValue({ success: true, ...VALID_TOKENS } as never);
    vi.spyOn(TwoFactorApiClient.prototype, 'useRecoveryCode').mockResolvedValue({ success: true, ...VALID_TOKENS } as never);
    vi.spyOn(TwoFactorApiClient.prototype, 'verifyV2').mockResolvedValue({ ...VALID_TOKENS } as never);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /** A fresh instance whose session() was set up after construction, counting createSession calls. */
  async function client() {
    const passflow = new Passflow({
      ...TEST_CONFIG,
      platform: createMockPlatform({ storage: localStorage }),
      refreshCoordination: 'none',
    });
    let created = 0;
    await passflow.session({
      createSession: async () => {
        created += 1;
      },
    });
    created = 0;
    return { passflow, created: () => created };
  }

  test.each<[string, (passflow: Passflow) => Promise<unknown>]>([
    ['signIn', (p) => p.signIn(CREDENTIALS)],
    ['signUp', (p) => p.signUp({ user: CREDENTIALS })],
    ['passkeyRegister', (p) => p.passkeyRegister({})],
  ])('%s', async (_name, complete) => {
    vi.spyOn(AuthAPI.prototype, 'signIn').mockResolvedValue({ ...VALID_TOKENS } as never);
    const c = await client();
    await complete(c.passflow);
    expect(c.created()).toBe(1);
  });

  test.each<[string, (passflow: Passflow) => Promise<unknown>]>([
    ['verifyTwoFactor', (p) => p.verifyTwoFactor('123456')],
    ['useTwoFactorRecoveryCode', (p) => p.useTwoFactorRecoveryCode('ABCD-EFGH-JKMN')],
    ['twoFactor.verifyV2', (p) => p.twoFactor.verifyV2({ challenge_id: 'c-1', method: 'totp', response: '123456' })],
  ])('%s after a sign-in that asked for a second factor', async (_name, complete) => {
    vi.spyOn(AuthAPI.prototype, 'signIn').mockResolvedValue({ ...PENDING } as never);
    const c = await client();
    await c.passflow.signIn(CREDENTIALS);
    expect(c.created()).toBe(0);
    await complete(c.passflow);
    expect(c.created()).toBe(1);
  });
});
