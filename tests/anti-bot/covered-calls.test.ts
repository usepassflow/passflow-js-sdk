/**
 * Covered versus uncovered calls on a human_only app with the built-in check.
 * Covered calls carry X-Passflow-Anti-Bot, each preceded by its own challenge POST.
 */
import { describe, expect, test } from 'vitest';
import {
  ANTI_BOT,
  attempt,
  CHALLENGE_PATH,
  COVERED,
  decodeHeader,
  EMAIL,
  type Harness,
  HUMAN_BUILTIN,
  HUMAN_NO_ANTI_BOT,
  harness,
  header,
  passwordlessPayload,
  SETTINGS_PATH,
  VECTOR_A,
  VECTOR_B,
} from './harness';

describe('covered calls on a human_only builtin app', () => {
  test.each(COVERED)(
    'REQ-1 $name: $route carries X-Passflow-Anti-Bot solving the challenge',
    async ({ run, route, identifier }) => {
      const h = harness(HUMAN_BUILTIN);
      await run(h);

      const covered = h.wire(route);
      expect(covered).toHaveLength(1);
      expect(covered[0].method).toBe('POST');
      const value = header(covered[0], ANTI_BOT);
      expect(value).toBeTruthy();
      expect(decodeHeader(value!)).toMatchObject({ number: 42, salt: VECTOR_A.salt, challenge: VECTOR_A.challenge });

      // Exactly one challenge, a POST, sent right before the covered call.
      const challenges = h.wire(CHALLENGE_PATH);
      expect(challenges).toHaveLength(1);
      expect(challenges[0].method).toBe('POST');
      expect(h.requests.indexOf(covered[0])).toBe(h.requests.indexOf(challenges[0]) + 1);
      expect((challenges[0].data as { identifier?: string } | undefined)?.identifier).toBe(identifier);
    },
  );

  test('REQ-1 the challenge request itself has no anti-bot header and no bearer', async () => {
    const h = harness(HUMAN_BUILTIN);
    await h.sdk.signIn({ email: EMAIL, password: 'Password123!' } as never);
    const [challenge] = h.wire(CHALLENGE_PATH);
    expect(header(challenge, ANTI_BOT)).toBeUndefined();
    expect(header(challenge, 'Authorization')).toBeUndefined();
  });

  test('REQ-1 the value is a header only: the request body carries no anti-bot field', async () => {
    const h = harness(HUMAN_BUILTIN);
    await h.sdk.signIn({ email: EMAIL, password: 'Password123!' } as never);
    const body = JSON.stringify(h.wire('/auth/login')[0].data);
    expect(body).not.toMatch(/anti|signature|salt|"number"/i);
  });

  test('REQ-1 a resend of passwordless start fetches a new challenge and sends a new value', async () => {
    const h = harness(HUMAN_BUILTIN);
    h.queue(CHALLENGE_PATH, VECTOR_A, VECTOR_B);
    await h.sdk.passwordlessSignIn(passwordlessPayload() as never);
    await h.sdk.passwordlessSignIn(passwordlessPayload() as never);

    expect(h.wire(CHALLENGE_PATH)).toHaveLength(2);
    const starts = h.wire('/auth/passwordless/start');
    expect(starts).toHaveLength(2);
    const [first, second] = starts.map((r) => header(r, ANTI_BOT)!);
    expect(first).not.toBe(second);
    expect(decodeHeader(first).number).toBe(42);
    expect(decodeHeader(second)).toMatchObject({ number: 1234, salt: VECTOR_B.salt });
  });
});

describe('uncovered calls carry no header and get no challenge', () => {
  const expectOnlyCoveredHaveHeader = (h: Harness, covered: string[]) => {
    for (const r of h.requests) {
      if (covered.includes(r.path)) continue;
      expect(header(r, ANTI_BOT), `${r.method} ${r.path}`).toBeUndefined();
    }
    h.requests.forEach((r, i) => {
      if (r.path === CHALLENGE_PATH) expect(covered).toContain(h.requests[i + 1]?.path);
    });
  };

  test('REQ-1 passwordless complete: no header, no challenge', async () => {
    const h = harness(HUMAN_BUILTIN);
    await attempt(h.sdk.passwordlessSignInComplete({ challenge_id: 'pl-1', otp: '123456' } as never));
    expect(h.wire('/auth/passwordless/complete')).toHaveLength(1);
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(0);
    expectOnlyCoveredHaveHeader(h, []);
  });

  test('REQ-1 app settings read: no header', async () => {
    const h = harness(HUMAN_BUILTIN);
    await h.sdk.signIn({ email: EMAIL, password: 'Password123!' } as never);
    const settings = h.wire(SETTINGS_PATH);
    expect(settings.length).toBeGreaterThanOrEqual(1);
    for (const r of settings) expect(header(r, ANTI_BOT)).toBeUndefined();
  });

  test('REQ-1 refresh after sign-in: no header, no challenge', async () => {
    const h = harness(HUMAN_BUILTIN);
    await h.sdk.signIn({ email: EMAIL, password: 'Password123!' } as never);
    h.clear();
    await attempt(h.sdk.refreshToken());
    expect(h.wire('/auth/refresh')).toHaveLength(1);
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(0);
    expectOnlyCoveredHaveHeader(h, []);
  });

  test('REQ-1 PKCE app: login is covered, pkce_exchange is not', async () => {
    const h = harness({ ...HUMAN_BUILTIN, pkce_enabled: true });
    h.reply('/auth/login', { code: 'authz-code' });
    await attempt(h.sdk.signIn({ email: EMAIL, password: 'Password123!' } as never));
    expect(header(h.wire('/auth/login')[0], ANTI_BOT)).toBeTruthy();
    const exchange = h.wire('/auth/pkce_exchange');
    expect(exchange).toHaveLength(1);
    expect(header(exchange[0], ANTI_BOT)).toBeUndefined();
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(1);
  });

  test('REQ-1 passkey complete calls carry no header', async () => {
    const h = harness(HUMAN_BUILTIN);
    await attempt(
      h.sdk.passkeyRegister({ relying_party_id: 'rp', redirect_url: 'https://app.example', scopes: ['id'] } as never),
    );
    await attempt(h.sdk.passkeyAuthenticate({ relying_party_id: 'rp' } as never));
    expect(h.wire('/auth/passkey/register/complete')).toHaveLength(1);
    expect(h.wire('/auth/passkey/authenticate/complete')).toHaveLength(1);
    expectOnlyCoveredHaveHeader(h, ['/auth/passkey/register/start', '/auth/passkey/authenticate/start']);
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(2);
  });
});

describe('human_only with no anti_bot means builtin', () => {
  test('REQ-2 sign in fetches a challenge and sends the solved value', async () => {
    const h = harness(HUMAN_NO_ANTI_BOT);
    await h.sdk.signIn({ email: EMAIL, password: 'Password123!' } as never);
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(1);
    expect(decodeHeader(header(h.wire('/auth/login')[0], ANTI_BOT)!).number).toBe(42);
  });
});
