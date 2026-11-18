import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AuthAPI } from '../../lib/api';
import { UpgradeAPI } from '../../lib/api/upgrade';
import { Passflow } from '../../lib/passflow';
import type { Tokens } from '../../lib/types';
import { totpFactor } from '../../lib/upgrade/factors';
import { TEST_CONFIG } from '../helpers/fixtures';
import { jwt } from '../refresh/jwt';
import { challengeResponse } from './fetch-fixtures';

const EXPIRED = 1_600_000_000;
const FUTURE = 4_102_444_800;
let issued = 0;

const pairOf = (iat: number, fresh = true): Tokens => {
  issued += 1;
  return {
    access_token: jwt({ sub: 'user-1', sid: 's1', exp: fresh ? FUTURE : EXPIRED, iat, jti: `a-${issued}`, type: 'access' }),
    refresh_token: jwt({ sub: 'user-1', sid: 's1', exp: FUTURE, iat, jti: `r-${issued}`, type: 'refresh' }),
    scopes: TEST_CONFIG.scopes,
  };
};

type Sent = { url: string; authorization: string | null };

describe('withAuth(fetch) attaches the access token to allowed origins only', () => {
  let sent: Sent[];
  let answers: Response[];
  const own = () => window.location.origin;

  /** What the network sees: a browser resolves a relative URL against the page. */
  const toRequest = (input: RequestInfo | URL, init?: RequestInit) =>
    input instanceof Request ? new Request(input, init) : new Request(new URL(String(input), own()), init);

  const recordingFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = toRequest(input, init);
    sent.push({ url: request.url, authorization: request.headers.get('authorization') });
    return answers.shift() ?? new Response('ok', { status: 200 });
  };

  const newPassflow = (tokens?: Tokens) => {
    const passflow = new Passflow({ ...TEST_CONFIG, refreshCoordination: 'none' });
    if (tokens) passflow.setTokens(tokens);
    return passflow;
  };

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    sent = [];
    answers = [];
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  test("the app's own origin gets the token, for an absolute and a relative URL", async () => {
    const tokens = pairOf(1_700_000_000);
    const authed = newPassflow(tokens).withAuth(recordingFetch);

    await authed(`${own()}/api/me`);
    await authed('/api/me');

    expect(sent.map((s) => s.authorization)).toEqual([`Bearer ${tokens.access_token}`, `Bearer ${tokens.access_token}`]);
  });

  test('a listed origin gets the token', async () => {
    const tokens = pairOf(1_700_000_000);
    const authed = newPassflow(tokens).withAuth(recordingFetch, { origins: ['https://api.example.com'] });

    await authed('https://api.example.com/transfer', { method: 'POST' });

    expect(sent[0]?.authorization).toBe(`Bearer ${tokens.access_token}`);
  });

  test.each([
    ['an unlisted origin', 'https://other.example.com/x'],
    ['a lookalike host', 'https://api.example.com.evil.com/x'],
    ['a lookalike with the listed host as a subdomain', 'https://evil.com/https://api.example.com/x'],
    ['a different port', 'https://api.example.com:8443/x'],
    ['http instead of https', 'http://api.example.com/x'],
    ['a third-party URL', 'https://cdn.thirdparty.net/lib.js'],
  ])('%s gets no token', async (_name, url) => {
    const authed = newPassflow(pairOf(1_700_000_000)).withAuth(recordingFetch, {
      origins: ['https://api.example.com'],
    });

    await authed(url);

    expect(sent[0]?.authorization).toBeNull();
  });

  test('an Authorization header the caller set is kept, as a header object, a Headers instance and on a Request', async () => {
    const authed = newPassflow(pairOf(1_700_000_000)).withAuth(recordingFetch);

    await authed('/api/a', { headers: { Authorization: 'Basic abc' } });
    await authed('/api/b', { headers: new Headers({ authorization: 'Bearer mine' }) });
    await authed(new Request(`${own()}/api/c`, { headers: { Authorization: 'Bearer request' } }));

    expect(sent.map((s) => s.authorization)).toEqual(['Basic abc', 'Bearer mine', 'Bearer request']);
  });

  test("other headers on the caller's request are kept when the token is added", async () => {
    const tokens = pairOf(1_700_000_000);
    const authed = newPassflow(tokens).withAuth(async (input, init) => {
      const request = toRequest(input, init);
      sent.push({ url: request.url, authorization: request.headers.get('authorization') });
      expect(request.headers.get('x-trace')).toBe('t-1');
      return new Response('ok');
    });

    await authed(new Request(`${own()}/api/c`, { headers: { 'X-Trace': 't-1' } }));

    expect(sent[0]?.authorization).toBe(`Bearer ${tokens.access_token}`);
  });

  test('an expired access token is refreshed once, then the new one is attached', async () => {
    const stale = pairOf(1_700_000_000, false);
    const fresh = pairOf(1_700_000_060);
    const refresh = vi.spyOn(AuthAPI.prototype, 'refreshToken').mockResolvedValue({ ...fresh } as never);
    const authed = newPassflow(stale).withAuth(recordingFetch);

    await authed('/api/me');
    await authed('/api/me');

    expect(refresh).toHaveBeenCalledTimes(1);
    expect(sent.map((s) => s.authorization)).toEqual([`Bearer ${fresh.access_token}`, `Bearer ${fresh.access_token}`]);
  });

  test('a listed entry counts by its origin, and one that is not a URL throws when the wrapper is built', async () => {
    const tokens = pairOf(1_700_000_000);
    const passflow = newPassflow(tokens);
    const authed = passflow.withAuth(recordingFetch, { origins: ['https://api.example.com/v1/'] });

    await authed('https://api.example.com/other');

    expect(sent[0]?.authorization).toBe(`Bearer ${tokens.access_token}`);
    expect(() => passflow.withAuth(recordingFetch, { origins: ['api.example.com'] })).toThrow();
  });

  test('signed out: no header is added', async () => {
    const authed = newPassflow().withAuth(recordingFetch);

    await authed('/api/me');

    expect(sent[0]?.authorization).toBeNull();
  });

  test('a step-up on a request whose token it attached replays with the new token', async () => {
    const before = pairOf(1_700_000_000);
    const after = pairOf(1_700_000_060);
    vi.spyOn(UpgradeAPI.prototype, 'startUpgrade').mockResolvedValue({
      challenge_id: 'c1',
      method: 'totp',
      expires_at: '2030-01-01T00:00:00Z',
    } as never);
    vi.spyOn(AuthAPI.prototype, 'refreshToken').mockResolvedValue({ ...after } as never);
    const passflow = newPassflow(before);
    const disable = passflow.upgrade.enable({
      factors: [totpFactor],
      backend: '/api',
      prompt: async (request) => {
        request.onFactorSelected('totp');
        return { type: 'submit', factor: 'totp', code: '123456' };
      },
    });
    answers = [challengeResponse(403)];
    try {
      const res = await passflow.withAuth(recordingFetch)('/api/transfer', { method: 'POST' });

      expect(res.status).toBe(200);
      expect(sent.map((s) => s.authorization)).toEqual([`Bearer ${before.access_token}`, `Bearer ${after.access_token}`]);
    } finally {
      disable();
    }
  });
});
