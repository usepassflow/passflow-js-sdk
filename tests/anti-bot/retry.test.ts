/**
 * 403 error.api.anti_bot.failed: the built-in check asks for a new challenge, solves it and resends
 * once; a second failure surfaces. required / unavailable are never resent, and BYO never is.
 */
import { describe, expect, test } from 'vitest';
import {
  ANTI_BOT_FAILED_ERROR_ID,
  ANTI_BOT_REQUIRED_ERROR_ID,
  ANTI_BOT_UNAVAILABLE_ERROR_ID,
  PassflowEvent,
} from '../../lib/index';
import { VALID_TOKENS } from '../helpers/fixtures';
import {
  ANTI_BOT,
  apiError,
  CHALLENGE_PATH,
  decodeHeader,
  EMAIL,
  fault,
  HUMAN_BUILTIN,
  HUMAN_BYO,
  harness,
  header,
  outcome,
  VECTOR_A,
  VECTOR_B,
} from './harness';

const FAILED = 'error.api.anti_bot.failed';
const signIn = (h: ReturnType<typeof harness>) => h.sdk.signIn({ email: EMAIL, password: 'Password123!' } as never);

describe('built-in check', () => {
  test('REQ-4 one 403 failed: a new challenge, a second login with a different value, and the sign-in succeeds', async () => {
    const h = harness(HUMAN_BUILTIN);
    h.queue(CHALLENGE_PATH, VECTOR_A, VECTOR_B);
    h.queue('/auth/login', apiError(FAILED, 403), { ...VALID_TOKENS });

    await expect(signIn(h)).resolves.toBeDefined();

    expect(h.wire(CHALLENGE_PATH)).toHaveLength(2);
    const logins = h.wire('/auth/login');
    expect(logins).toHaveLength(2);
    const [first, second] = logins.map((r) => header(r, ANTI_BOT)!);
    expect(first).not.toBe(second);
    expect(decodeHeader(first).number).toBe(42);
    expect(decodeHeader(second).number).toBe(1234);
    // The resend is the same request: same body.
    expect(logins[1].data).toEqual(logins[0].data);
    // The order is challenge, login, challenge, login.
    expect(h.requests.filter((r) => r.path === CHALLENGE_PATH || r.path === '/auth/login').map((r) => r.path)).toEqual([
      CHALLENGE_PATH,
      '/auth/login',
      CHALLENGE_PATH,
      '/auth/login',
    ]);
    expect(h.of(PassflowEvent.Error)).toHaveLength(0);
  });

  test('REQ-4 two 403 failed: exactly two challenges and two logins, then the error surfaces with one Error event', async () => {
    const h = harness(HUMAN_BUILTIN);
    h.queue(CHALLENGE_PATH, VECTOR_A, VECTOR_B, VECTOR_A);
    h.reply('/auth/login', apiError(FAILED, 403));

    const error = await outcome(signIn(h));
    expect((error as { id?: string }).id).toBe(ANTI_BOT_FAILED_ERROR_ID);
    expect(ANTI_BOT_FAILED_ERROR_ID).toBe(FAILED);
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(2);
    expect(h.wire('/auth/login')).toHaveLength(2);

    const errors = h.of(PassflowEvent.Error) as Array<{ operation?: string; code?: string }>;
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatchObject({ operation: 'sign-in', code: FAILED });
  });

  test('REQ-4 403 required: one login, no resend, the id is kept', async () => {
    const h = harness(HUMAN_BUILTIN);
    h.reply('/auth/login', apiError('error.api.anti_bot.required', 403));
    const error = await outcome(signIn(h));
    expect((error as { id?: string }).id).toBe(ANTI_BOT_REQUIRED_ERROR_ID);
    expect(ANTI_BOT_REQUIRED_ERROR_ID).toBe('error.api.anti_bot.required');
    expect(h.wire('/auth/login')).toHaveLength(1);
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(1);
  });

  test('REQ-4 503 unavailable with Retry-After 5: one login, no resend, the id is kept', async () => {
    const h = harness(HUMAN_BUILTIN);
    const unavailable = apiError('error.api.anti_bot.unavailable', 503);
    h.reply('/auth/login', { ...unavailable, headers: { 'retry-after': '5' } });
    const error = await outcome(signIn(h));
    expect((error as { id?: string; status?: number }).id).toBe(ANTI_BOT_UNAVAILABLE_ERROR_ID);
    expect(ANTI_BOT_UNAVAILABLE_ERROR_ID).toBe('error.api.anti_bot.unavailable');
    expect(h.wire('/auth/login')).toHaveLength(1);
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(1);
  });

  test('REQ-4 a failing challenge request surfaces and sends no sign-in', async () => {
    const h = harness(HUMAN_BUILTIN);
    h.reply(CHALLENGE_PATH, fault(429, { error: { id: 'error.api.rate_limit', message: 'slow down', status: 429 } }));
    await outcome(signIn(h));
    expect(h.wire('/auth/login')).toHaveLength(0);
  });
});

describe('BYO provider', () => {
  test('REQ-4 403 failed is never resent: one login, one provider call', async () => {
    const h = harness(HUMAN_BYO);
    const calls: unknown[] = [];
    h.sdk.setAntiBotTokenProvider(async (ctx) => {
      calls.push(ctx);
      return `byo-token-${calls.length}`;
    });
    h.reply('/auth/login', apiError(FAILED, 403));

    const error = await outcome(signIn(h));
    expect((error as { id?: string }).id).toBe(FAILED);
    expect(h.wire('/auth/login')).toHaveLength(1);
    expect(calls).toHaveLength(1);
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(0);
  });
});
