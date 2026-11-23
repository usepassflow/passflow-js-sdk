/**
 * passflow.antiBotToken(): a fresh header value for requests core does not send itself.
 */
import { describe, expect, test } from 'vitest';
import { ANTI_BOT_HEADER_KEY } from '../../lib/index';
import {
  BOT_FRIENDLY,
  CHALLENGE_PATH,
  DEVICE_CHALLENGE_PATH,
  decodeHeader,
  EMAIL,
  HUMAN_BUILTIN,
  HUMAN_BYO,
  harness,
  header,
  VECTOR_A_HEADER,
  VECTOR_B,
} from './harness';

describe('antiBotToken', () => {
  test('REQ-9 the header name is X-Passflow-Anti-Bot', () => {
    expect(ANTI_BOT_HEADER_KEY).toBe('X-Passflow-Anti-Bot');
  });

  test('REQ-9 bot_friendly: undefined and no challenge', async () => {
    const h = harness(BOT_FRIENDLY);
    await expect(h.sdk.antiBotToken({ operation: 'session.exchange' })).resolves.toBeUndefined();
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(0);
    expect(h.wire(DEVICE_CHALLENGE_PATH)).toHaveLength(0);
  });

  test('REQ-9 human_only builtin, session.exchange: the /auth challenge, solved value returned', async () => {
    const h = harness(HUMAN_BUILTIN);
    await expect(h.sdk.antiBotToken({ operation: 'session.exchange' })).resolves.toBe(VECTOR_A_HEADER);
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(1);
  });

  test('REQ-9 each call fetches its own challenge and returns a different value', async () => {
    const h = harness(HUMAN_BUILTIN);
    const first = await h.sdk.antiBotToken({ operation: 'session.exchange' });
    h.reply(CHALLENGE_PATH, VECTOR_B);
    const second = await h.sdk.antiBotToken({ operation: 'session.exchange' });
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(2);
    expect(first).not.toBe(second);
  });

  test('REQ-9 BYO: returns the provider token for the operation', async () => {
    const h = harness(HUMAN_BYO);
    const seen: unknown[] = [];
    h.sdk.setAntiBotTokenProvider(async (ctx) => {
      seen.push(ctx);
      return 'byo';
    });
    await expect(h.sdk.antiBotToken({ operation: 'session.exchange' })).resolves.toBe('byo');
    expect(seen).toEqual([{ action: 'passflow_auth', operation: 'session.exchange' }]);
  });

  test('REQ-9 device page: settings passed in, POST /oidc/device/anti-bot/challenge with user_code, identifier and CSRF, no bearer', async () => {
    // The app itself is bot_friendly and the user is signed in: the passed settings decide, and
    // the device challenge must still carry no bearer.
    const h = harness(BOT_FRIENDLY);
    await h.sdk.signIn({ email: EMAIL, password: 'Password123!' } as never);
    h.clear();

    const value = await h.sdk.antiBotToken({
      operation: 'device.authenticate',
      identifier: EMAIL,
      settings: { bot_mode: 'human_only' } as never,
      device: { userCode: 'ABCD-EFGH', csrfToken: 'csrf-123' },
    });

    expect(h.wire(CHALLENGE_PATH)).toHaveLength(0);
    const [challenge] = h.wire(DEVICE_CHALLENGE_PATH);
    expect(challenge.method).toBe('POST');
    expect(challenge.data).toEqual({ user_code: 'ABCD-EFGH', identifier: EMAIL });
    expect(header(challenge, 'X-Passflow-CSRF')).toBe('csrf-123');
    expect(header(challenge, 'Authorization')).toBeUndefined();
    expect(decodeHeader(value!).number).toBe(42);
    // The helper sends nothing but the challenge.
    expect(h.requests.map((r) => r.path)).toEqual([DEVICE_CHALLENGE_PATH]);
  });

  test('REQ-9 device page with bot_friendly settings: undefined and no request', async () => {
    const h = harness(HUMAN_BUILTIN);
    const value = await h.sdk.antiBotToken({
      operation: 'device.passkey.start',
      settings: { bot_mode: 'bot_friendly' } as never,
      device: { userCode: 'ABCD-EFGH', csrfToken: 'csrf-123' },
    });
    expect(value).toBeUndefined();
    expect(h.wire(DEVICE_CHALLENGE_PATH)).toHaveLength(0);
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(0);
  });
});
