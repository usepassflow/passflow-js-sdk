/**
 * Bring-your-own provider: setAntiBotTokenProvider's token is the header value as it is.
 */
import { describe, expect, test } from 'vitest';
import {
  ANTI_BOT_ACTION,
  ANTI_BOT_PROVIDER_FAILED_ERROR_ID,
  ANTI_BOT_PROVIDER_MISSING_ERROR_ID,
  PassflowEvent,
} from '../../lib/index';
import {
  ANTI_BOT,
  BOT_FRIENDLY,
  CHALLENGE_PATH,
  EMAIL,
  HUMAN_BYO,
  harness,
  header,
  outcome,
  passwordlessPayload,
} from './harness';

const signIn = (h: ReturnType<typeof harness>) => h.sdk.signIn({ email: EMAIL, password: 'Password123!' } as never);

describe('BYO provider', () => {
  test('REQ-5 the provider gets {action: passflow_auth, operation} and its token is the header as-is; no challenge', async () => {
    const h = harness(HUMAN_BYO);
    const contexts: unknown[] = [];
    const token = 'tt.0/AbC+xyz==';
    h.sdk.setAntiBotTokenProvider(async (ctx) => {
      contexts.push(ctx);
      return token;
    });

    await signIn(h);
    await h.sdk.passwordlessSignIn(passwordlessPayload() as never);

    expect(h.wire(CHALLENGE_PATH)).toHaveLength(0);
    expect(header(h.wire('/auth/login')[0], ANTI_BOT)).toBe(token);
    expect(header(h.wire('/auth/passwordless/start')[0], ANTI_BOT)).toBe(token);
    expect(contexts).toEqual([
      { action: 'passflow_auth', operation: 'sign-in' },
      { action: 'passflow_auth', operation: 'passwordless.start' },
    ]);
    expect(ANTI_BOT_ACTION).toBe('passflow_auth');
  });

  test('REQ-5 a provider written as () => Promise<string> works', async () => {
    const h = harness(HUMAN_BYO);
    h.sdk.setAntiBotTokenProvider(() => Promise.resolve('no-arg-token'));
    await signIn(h);
    expect(header(h.wire('/auth/login')[0], ANTI_BOT)).toBe('no-arg-token');
  });

  test('REQ-5 no provider set: rejects with provider_missing, no sign-in request, one Error event', async () => {
    const h = harness(HUMAN_BYO);
    const error = await outcome(signIn(h));
    expect((error as { id?: string }).id).toBe(ANTI_BOT_PROVIDER_MISSING_ERROR_ID);
    expect(ANTI_BOT_PROVIDER_MISSING_ERROR_ID).toBe('error.anti_bot.provider_missing');
    expect((error as Error).message).toMatch(/setAntiBotTokenProvider/);
    expect(h.wire('/auth/login')).toHaveLength(0);
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(0);
    const errors = h.of(PassflowEvent.Error) as Array<{ operation?: string; code?: string }>;
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatchObject({ operation: 'sign-in', code: ANTI_BOT_PROVIDER_MISSING_ERROR_ID });
  });

  test('REQ-5 the provider unset with undefined behaves as no provider', async () => {
    const h = harness(HUMAN_BYO);
    h.sdk.setAntiBotTokenProvider(async () => 'x');
    h.sdk.setAntiBotTokenProvider(undefined);
    const error = await outcome(signIn(h));
    expect((error as { id?: string }).id).toBe(ANTI_BOT_PROVIDER_MISSING_ERROR_ID);
    expect(h.wire('/auth/login')).toHaveLength(0);
  });

  test('REQ-5 the provider rejects: provider_failed, no sign-in request', async () => {
    const h = harness(HUMAN_BYO);
    h.sdk.setAntiBotTokenProvider(() => Promise.reject(new Error('widget closed')));
    const error = await outcome(signIn(h));
    expect((error as { id?: string }).id).toBe(ANTI_BOT_PROVIDER_FAILED_ERROR_ID);
    expect(ANTI_BOT_PROVIDER_FAILED_ERROR_ID).toBe('error.anti_bot.provider_failed');
    expect(h.wire('/auth/login')).toHaveLength(0);
  });

  test("REQ-5 the provider resolves '': provider_failed, no sign-in request", async () => {
    const h = harness(HUMAN_BYO);
    h.sdk.setAntiBotTokenProvider(async () => '');
    const error = await outcome(signIn(h));
    expect((error as { id?: string }).id).toBe(ANTI_BOT_PROVIDER_FAILED_ERROR_ID);
    expect(h.wire('/auth/login')).toHaveLength(0);
  });

  test('REQ-5 a provider set on a bot_friendly app is never called', async () => {
    const h = harness(BOT_FRIENDLY);
    let called = 0;
    h.sdk.setAntiBotTokenProvider(async () => {
      called += 1;
      return 'never';
    });
    await signIn(h);
    expect(called).toBe(0);
    expect(header(h.wire('/auth/login')[0], ANTI_BOT)).toBeUndefined();
  });
});
