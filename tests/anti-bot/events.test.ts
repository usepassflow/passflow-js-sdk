/**
 * anti-bot:solving and anti-bot:solved fire once each per produced value, before the request.
 */
import { describe, expect, test } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import { VALID_TOKENS } from '../helpers/fixtures';
import {
  apiError,
  attempt,
  CHALLENGE_PATH,
  EMAIL,
  HUMAN_BUILTIN,
  HUMAN_BYO,
  harness,
  passwordlessPayload,
  VECTOR_A,
  VECTOR_B,
} from './harness';

const signIn = (h: ReturnType<typeof harness>) => h.sdk.signIn({ email: EMAIL, password: 'Password123!' } as never);

describe('progress events', () => {
  test('REQ-7 event names are anti-bot:solving and anti-bot:solved', () => {
    expect(PassflowEvent.AntiBotSolving).toBe('anti-bot:solving');
    expect(PassflowEvent.AntiBotSolved).toBe('anti-bot:solved');
  });

  test('REQ-7 builtin: solving then solved once each, then the covered request, with {operation, provider}', async () => {
    const h = harness(HUMAN_BUILTIN);
    await signIn(h);
    expect(h.antiBotEvents()).toEqual([
      { event: PassflowEvent.AntiBotSolving, payload: { operation: 'sign-in', provider: 'builtin' } },
      { event: PassflowEvent.AntiBotSolved, payload: { operation: 'sign-in', provider: 'builtin' } },
    ]);
    const t = h.timeline;
    const solving = t.indexOf(`event:${PassflowEvent.AntiBotSolving}`);
    const solved = t.indexOf(`event:${PassflowEvent.AntiBotSolved}`);
    const login = t.indexOf('request:/auth/login');
    expect(solving).toBeGreaterThanOrEqual(0);
    expect(solving).toBeLessThan(solved);
    expect(solved).toBeLessThan(login);
  });

  test('REQ-7 BYO: one pair with the provider name', async () => {
    const h = harness(HUMAN_BYO);
    h.sdk.setAntiBotTokenProvider(async () => 'tok');
    await h.sdk.passwordlessSignIn(passwordlessPayload() as never);
    expect(h.antiBotEvents()).toEqual([
      { event: PassflowEvent.AntiBotSolving, payload: { operation: 'passwordless.start', provider: 'turnstile' } },
      { event: PassflowEvent.AntiBotSolved, payload: { operation: 'passwordless.start', provider: 'turnstile' } },
    ]);
  });

  test('REQ-7 a retry after 403 failed gives a second pair', async () => {
    const h = harness(HUMAN_BUILTIN);
    h.queue(CHALLENGE_PATH, VECTOR_A, VECTOR_B);
    h.queue('/auth/login', apiError('error.api.anti_bot.failed', 403), { ...VALID_TOKENS });
    await signIn(h);
    expect(h.antiBotEvents().map((e) => e.event)).toEqual([
      PassflowEvent.AntiBotSolving,
      PassflowEvent.AntiBotSolved,
      PassflowEvent.AntiBotSolving,
      PassflowEvent.AntiBotSolved,
    ]);
  });

  test('REQ-7 a failure gives solving and no solved', async () => {
    const h = harness(HUMAN_BYO);
    h.sdk.setAntiBotTokenProvider(() => Promise.reject(new Error('no')));
    await attempt(signIn(h));
    expect(h.antiBotEvents().map((e) => e.event)).toEqual([PassflowEvent.AntiBotSolving]);
  });
});
