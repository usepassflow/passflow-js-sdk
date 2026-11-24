/**
 * A new sign-in replaces the stored session as a whole: no token of the previous session is left
 * beside the new ones. A refresh answer, which continues the session, still keeps the stored tokens
 * it does not name. Real `Passflow` instances as tabs (tests/refresh/sdk-tabs.ts).
 */
import { URLSearchParams as NativeURLSearchParams } from 'node:url';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { AppAPI, AuthAPI } from '../../lib/api';
import { PassflowEvent } from '../../lib/store';
import type { Tokens } from '../../lib/types';
import { TEST_CONFIG } from '../helpers/fixtures';
import { jwt } from './jwt';
import { accessOnlyOf, createSdkWorld, FUTURE, openTab, pairOf, type SdkWorld } from './sdk-tabs';

// Signature checks of URL tokens are covered in tests/integration/url-token-verification.test.ts.
vi.mock('../../lib/token/verify', () => ({ verifyUrlTokens: async () => undefined }));

const KEYS = { access: 'access', refresh: 'refresh', id: 'id_token', scopes: 'tokens_scopes' };
const COOKIE_ID = 'passflow_id_token';

let world: SdkWorld | undefined;
const start = (answer?: Parameters<typeof createSdkWorld>[0]): SdkWorld => {
  world = createSdkWorld(answer);
  // A Simple-mode app: sign-in runs without PKCE and URL tokens are accepted.
  vi.spyOn(AppAPI.prototype, 'getAppSettings').mockResolvedValue({ pkce_enabled: false } as never);
  return world;
};

afterEach(() => {
  world?.dispose();
  world = undefined;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const idToken = (label: string, aud?: string): string =>
  jwt({ sub: 'user-1', exp: FUTURE, jti: label, ...(aud ? { aud: [aud] } : {}) });
const fullSet = (fresh = true): Tokens => ({
  ...pairOf('user-1', { fresh }),
  id_token: idToken('old'),
  scopes: ['old-1', 'old-2'],
});

/** Which token of `expected` each key holds, so a failure names the key and prints no token. */
const expectStored = (w: SdkWorld, expected: Tokens): void => {
  const same = (key: string, value: string | undefined) =>
    w.shared.items.get(key) === value ? 'as expected' : w.shared.items.has(key) ? 'another value' : 'absent';
  expect({
    access: same(KEYS.access, expected.access_token),
    refresh: same(KEYS.refresh, expected.refresh_token),
    id: same(KEYS.id, expected.id_token),
    scopes: same(KEYS.scopes, expected.scopes?.join(',')),
  }).toEqual({ access: 'as expected', refresh: 'as expected', id: 'as expected', scopes: 'as expected' });
};

/** One tab: a full set, then an access-only sign-in of the same user through setTokens. */
async function replaced(next: Tokens = accessOnlyOf()) {
  const w = start();
  const old = fullSet();
  const a = openTab(w, 'a');
  a.passflow.setTokens(old);
  await w.run();
  a.passflow.setTokens(next);
  await w.ready();
  return { w, a, next };
}

describe('an access-only setTokens over a full set', () => {
  test('storage holds only the new access token', async () => {
    const { w, next } = await replaced();
    expectStored(w, next);
  });

  test('the next foreground adopts nothing', async () => {
    const { w, a, next } = await replaced();
    a.foreground();
    await w.run(3_000);
    expect(a.names()).toEqual([]);
    expect(a.passflow.getCachedTokens()?.access_token === next.access_token).toBe(true);
    expect(a.passflow.getCachedTokens()?.refresh_token === undefined).toBe(true);
  });

  test('refreshToken() sends no token of the replaced session', async () => {
    const { w, a } = await replaced();
    const call = w.track(a.passflow.refreshToken());
    await w.run(10);
    // Each request holds a token, so only their number is compared.
    expect(w.requests.length).toBe(0);
    expect(call.status).toBe('rejected');
  });

  test.each(['user-1', 'user-2'])('a page load does not pair the old refresh token (new session of %s)', async (sub) => {
    const { w, a, next } = await replaced(accessOnlyOf(sub));
    w.kill(a);
    const b = openTab(w, 'b');
    await w.run();
    expect(b.passflow.getCachedTokens()?.access_token === next.access_token).toBe(true);
    expect(b.passflow.getCachedTokens()?.refresh_token === undefined).toBe(true);
  });
});

describe('a full-pair tab beside an access-only sign-in of the same user', () => {
  test('signs out after 2000 ms, and the tab that signed in stays signed in', async () => {
    const w = start();
    const next = accessOnlyOf();
    w.seed(pairOf('user-1', { fresh: true }));
    const a = openTab(w, 'a');
    const b = openTab(w, 'b');
    await w.ready();

    b.passflow.setTokens(next);
    await w.run(1_999);
    expect(a.names()).toEqual([]);
    expect(a.passflow.isAuthenticated()).toBe(true);
    await w.run(1);

    expect(a.names()).toEqual([PassflowEvent.SignOut]);
    expect(a.of<{ origin?: string }>(PassflowEvent.SignOut).map((p) => p.origin)).toEqual(['other-tab']);
    expect(a.passflow.getCachedTokens() === undefined).toBe(true);
    await w.run(3_000);
    expect(b.names()).toEqual([PassflowEvent.SignIn]);
    expect(b.passflow.isAuthenticated()).toBe(true);
    expectStored(w, next);
  });
});

describe('scopes the new session does not name', () => {
  const otherRefresh = jwt({ sub: 'user-9', aud: ['other-app'], exp: FUTURE, iat: 1, type: 'refresh' });
  const otherId = idToken('other', 'other-app');

  test("stay, with the tokens, when only another app's session is stored", async () => {
    const w = start();
    w.seed({ refresh_token: otherRefresh, id_token: otherId, scopes: ['other-1', 'other-2'] } as Tokens);
    const a = openTab(w, 'a');
    await w.ready();

    a.passflow.setTokens(accessOnlyOf());
    await w.run();

    expect(w.shared.items.get(KEYS.scopes)).toBe('other-1,other-2');
    expect(w.shared.items.get(KEYS.refresh) === otherRefresh).toBe(true);
    expect(w.shared.items.get(KEYS.id) === otherId).toBe(true);
  });

  test("go when this app's session is stored, also beside another app's token", async () => {
    const w = start();
    w.seed({ ...fullSet(), id_token: otherId });
    const a = openTab(w, 'a');
    await w.ready();

    a.passflow.setTokens(accessOnlyOf());
    await w.run();

    expect(w.shared.items.has(KEYS.scopes)).toBe(false);
    expect(w.shared.items.has(KEYS.refresh)).toBe(false);
    expect(w.shared.items.get(KEYS.id) === otherId).toBe(true);
  });
});

describe('other access-only sign-ins over a full set', () => {
  test('tokens in the URL replace the stored session', async () => {
    // The test setup replaces URLSearchParams with a mock that does not parse a query string.
    vi.stubGlobal('URLSearchParams', NativeURLSearchParams);
    const w = start();
    w.seed(fullSet());
    const next = accessOnlyOf();
    const a = openTab(w, 'a', {
      getCurrentUrl: vi.fn(() => ({
        href: `https://app.example/?access_token=${next.access_token}`,
        origin: 'https://app.example',
        pathname: '/',
        search: `?access_token=${next.access_token}`,
        hash: '',
        hostname: 'app.example',
      })),
    });
    await w.ready();

    a.passflow.handleTokensRedirect();
    await w.run();

    expect(a.of<{ source?: string }>(PassflowEvent.SignIn).map((p) => p.source)).toEqual(['tokens-in-url']);
    // The URL names no scopes, so the session has the configured ones.
    expectStored(w, { ...next, scopes: TEST_CONFIG.scopes });
  });

  test('signIn() answered access-only replaces the stored session', async () => {
    const w = start();
    w.seed(fullSet());
    const a = openTab(w, 'a');
    await w.ready();
    const next = accessOnlyOf();
    vi.spyOn(AuthAPI.prototype, 'signIn').mockResolvedValue({ ...next } as never);

    const call = w.track(a.passflow.signIn({ email: 'x@example.com', password: 'p' }));
    await w.run();

    expect(call.status).toBe('resolved');
    expectStored(w, { ...next, scopes: TEST_CONFIG.scopes });
  });
});

describe('what stays', () => {
  test('a refresh answer without refresh_token or id_token keeps the stored ones', async () => {
    const answer = accessOnlyOf();
    const w = start(() => ({ tokens: answer }));
    const old = fullSet(false);
    w.seed(old);
    const a = openTab(w, 'a');
    await w.ready();

    const call = w.track(a.passflow.refreshToken());
    await w.run(10);

    expect(call.status).toBe('resolved');
    expect(w.shared.items.get(KEYS.access) === answer.access_token).toBe(true);
    expect(w.shared.items.get(KEYS.refresh) === old.refresh_token).toBe(true);
    expect(w.shared.items.get(KEYS.id) === old.id_token).toBe(true);
  });

  test("another app's tokens under the shared keys", async () => {
    const w = start();
    const refresh = jwt({ sub: 'user-9', aud: ['other-app'], exp: FUTURE, iat: 1, type: 'refresh' });
    const id = idToken('other', 'other-app');
    w.seed({ refresh_token: refresh, id_token: id } as Tokens);
    const a = openTab(w, 'a');
    await w.ready();

    a.passflow.setTokens(accessOnlyOf());
    await w.run();

    expect(w.shared.items.get(KEYS.refresh) === refresh).toBe(true);
    expect(w.shared.items.get(KEYS.id) === id).toBe(true);
  });

  test('in cookie mode, the mode, the CSRF token and the stored id token', async () => {
    const w = start();
    // A cookie-mode tab checks its session with the server on load. The check stays unanswered here:
    // its answer would write the session state into the shared storage.
    vi.spyOn(AuthAPI.prototype, 'validateSession').mockReturnValue(new Promise(() => {}));
    const id = idToken('cookie');
    w.shared.items.set('passflow_delivery_mode', 'cookie');
    w.shared.items.set('passflow_csrf_token', 'csrf');
    w.shared.items.set(COOKIE_ID, id);
    const a = openTab(w, 'a', { cookiesSupported: vi.fn(() => true) });
    await w.ready();
    const before = w.snapshot();

    a.passflow.setTokens(accessOnlyOf());
    await w.run();

    expect(Object.keys(w.snapshot())).toEqual(Object.keys(before));
    expect(w.shared.items.get('passflow_delivery_mode')).toBe('cookie');
    expect(w.shared.items.get('passflow_csrf_token')).toBe('csrf');
    expect(w.shared.items.get(COOKIE_ID) === id).toBe(true);

    const next = idToken('cookie-next');
    a.passflow.setTokens({ ...accessOnlyOf(), id_token: next });
    await w.run();

    expect(Object.keys(w.snapshot())).toEqual(Object.keys(before));
    expect(w.shared.items.get(COOKIE_ID) === next).toBe(true);
  });

  test('a full set given to setTokens is stored whole, over an access-only session or an earlier full set', async () => {
    const w = start();
    const a = openTab(w, 'a');
    for (const before of [accessOnlyOf(), { ...fullSet(), scopes: ['earlier'] }]) {
      const next: Tokens = { ...fullSet(), id_token: idToken('new') };
      a.passflow.setTokens(before);
      await w.run();
      a.passflow.setTokens(next);
      await w.run();
      expectStored(w, next);
    }
  });
});
