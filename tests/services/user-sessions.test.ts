/**
 * The signed-in user's sessions through the public `Passflow` API.
 *
 * - `listSessions()` is `GET /user/sessions` and resolves to the `sessions` array of the reply.
 * - `revokeSession(id)` is `DELETE /user/sessions/{id}` (id URL-encoded) and resolves to nothing.
 *   When `id` is the current session (the `sid` of the stored access token, else of the stored ID
 *   token) it then signs out like `logOut()`: stored tokens go, exactly one `SignOut`, and the hosted
 *   end-session navigation when the sign-in was hosted. A failed DELETE rejects, reports one `Error`
 *   with `operation: 'session.revoke'`, and does not sign out.
 * - `signOutOtherSessions()` is `POST /user/sessions/revoke-others`, resolves to `{ revoked }` and
 *   changes nothing locally.
 *
 * Every request goes over the real axios path; replies come from the harness adapter.
 */
import { describe, expect, expectTypeOf, test } from 'vitest';
import {
  type Passflow,
  PassflowEvent,
  type PassflowRevokeOtherSessionsResponse,
  type PassflowSessionDevice,
  type PassflowUserSession,
  type PassflowUserSessionList,
} from '../../lib/index';
import { TEST_CONFIG } from '../helpers/fixtures';
import { drive, modeHarness, PAGE, publishKey, SIMPLE_APP, settle } from '../helpers/oidc-harness';
import { fault, type Harness, harness, until } from '../helpers/pkce-harness';
import { issuedTokens, tokenParams, unsignedToken } from '../helpers/signed-tokens';

const SESSIONS = '/user/sessions';
const REVOKE_OTHERS = '/user/sessions/revoke-others';
const LOGOUT = '/user/logout';
const REFRESH = '/auth/refresh';
const END_SESSION = `${TEST_CONFIG.url}/oidc/end_session`;

const CURRENT_SID = 'session-current-1';
const OTHER_SID = 'session-other-2';

const now = () => Math.floor(Date.now() / 1000);

/** A token set for this app; `access`/`id` claims go on those tokens only. */
function tokensFor(claims: { access?: Record<string, unknown>; id?: Record<string, unknown> } = {}) {
  const base = { sub: 'user-sessions-1', aud: [TEST_CONFIG.appId], iss: 'test-issuer', iat: now(), exp: now() + 3600 };
  return {
    access_token: unsignedToken({ ...base, type: 'access', jti: 'sessions-access', ...claims.access }),
    refresh_token: unsignedToken({ ...base, type: 'refresh', jti: 'sessions-refresh', exp: now() + 86_400 }),
    id_token: unsignedToken({ ...base, jti: 'sessions-id', email: 'sessions@example.com', ...claims.id }),
    scopes: ['id', 'offline', 'email', 'openid'],
  };
}

type Seeded = ReturnType<typeof tokensFor>;

/** A signed-in harness: tokens stored, events cleared, revoke and logout answered `ok`. */
function signedIn(tokens: Seeded = tokensFor({ access: { sid: CURRENT_SID }, id: { sid: CURRENT_SID } })) {
  const h = harness();
  h.sdk.setTokens(tokens);
  h.clearEvents();
  h.reply(LOGOUT, { status: 'ok' });
  h.reply(`${SESSIONS}/${CURRENT_SID}`, { status: 'ok' });
  h.reply(`${SESSIONS}/${OTHER_SID}`, { status: 'ok' });
  return { h, tokens };
}

/** The seeded token strings still held in localStorage, under any key the SDK ever wrote. */
function storedTokenStrings(h: Harness, tokens: Seeded) {
  const keys = new Set(h.writes.map((w) => w.key));
  const joined = [...keys].map((key) => localStorage.getItem(key) ?? '').join('\n');
  return [tokens.access_token, tokens.refresh_token, tokens.id_token].filter((t) => joined.includes(t));
}

function expectStillSignedIn(h: Harness, tokens: Seeded) {
  expect(h.of(PassflowEvent.SignOut)).toEqual([]);
  expect(h.sdk.isAuthenticated()).toBe(true);
  expect(h.sdk.getCachedTokens()?.access_token).toBe(tokens.access_token);
  expect(h.wire(LOGOUT)).toHaveLength(0);
}

function expectSignedOut(h: Harness, tokens: Seeded) {
  expect(h.of(PassflowEvent.SignOut)).toHaveLength(1);
  expect(h.sdk.isAuthenticated()).toBe(false);
  expect(h.sdk.getCachedTokens()?.access_token).toBeUndefined();
  expect(storedTokenStrings(h, tokens)).toEqual([]);
}

const errorsOf = (h: Harness) => h.of(PassflowEvent.Error) as Array<{ operation?: string }>;

const SERVER_SESSIONS: PassflowUserSession[] = [
  {
    id: CURRENT_SID,
    app_id: TEST_CONFIG.appId,
    created_at: '2026-11-20T10:00:00Z',
    auth_time: '2026-11-20T10:00:00Z',
    expires_at: '2026-12-20T10:00:00Z',
    current: true,
    device: {
      name: 'Firefox on Linux',
      type: 'web',
      user_agent: 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0',
      ip: '203.0.113.7',
      location: 'Sydney, AU',
      last_seen: '2026-11-21T08:00:00Z',
    },
  },
  {
    id: OTHER_SID,
    app_id: TEST_CONFIG.appId,
    created_at: '2026-11-01T09:00:00Z',
    auth_time: '2026-11-01T09:00:00Z',
    current: false,
    device: { type: 'a-type-the-server-added-later' },
  },
];

describe('listSessions', () => {
  test('sends GET /user/sessions and resolves to the sessions array of the reply', async () => {
    const { h, tokens } = signedIn();
    h.reply(SESSIONS, { sessions: SERVER_SESSIONS });

    const result = await drive(h.sdk.listSessions());

    expect(result).toEqual({ ok: true, value: SERVER_SESSIONS });
    const sent = h.wire(SESSIONS);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.method?.toUpperCase()).toBe('GET');
    expectStillSignedIn(h, tokens);
    expect(h.wire(REFRESH)).toHaveLength(0);
  });

  test('resolves to an empty array when the server lists no sessions', async () => {
    const { h } = signedIn();
    h.reply(SESSIONS, { sessions: [] });

    expect(await drive(h.sdk.listSessions())).toEqual({ ok: true, value: [] });
  });

  test('a failed list rejects and reports one Error with operation session.list', async () => {
    const { h, tokens } = signedIn();
    h.reply(SESSIONS, fault('http', 500, { error: { id: 'error.internal', message: 'boom' } }));

    const result = await drive(h.sdk.listSessions());

    expect(result.ok).toBe(false);
    expect(errorsOf(h)).toHaveLength(1);
    expect(errorsOf(h)[0]).toMatchObject({ operation: 'session.list' });
    expectStillSignedIn(h, tokens);
  });
});

describe('signOutOtherSessions', () => {
  test('sends POST /user/sessions/revoke-others and resolves to { revoked }', async () => {
    const { h } = signedIn();
    h.reply(REVOKE_OTHERS, { revoked: 3 });

    const result = await drive(h.sdk.signOutOtherSessions());

    expect(result).toEqual({ ok: true, value: { revoked: 3 } });
    const sent = h.wire(REVOKE_OTHERS);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.method?.toUpperCase()).toBe('POST');
  });

  test('changes nothing locally: tokens stay stored, no SignOut, no logout request', async () => {
    const { h, tokens } = signedIn();
    h.reply(REVOKE_OTHERS, { revoked: 1 });

    await drive(h.sdk.signOutOtherSessions());
    await settle();

    expectStillSignedIn(h, tokens);
    expect(storedTokenStrings(h, tokens)).toContain(tokens.access_token);
    expect(h.of(PassflowEvent.Error)).toEqual([]);
    expect(h.navigations).toEqual([]);
  });

  test('resolves { revoked: 0 } when there were no other sessions', async () => {
    const { h } = signedIn();
    h.reply(REVOKE_OTHERS, { revoked: 0 });

    expect(await drive(h.sdk.signOutOtherSessions())).toEqual({ ok: true, value: { revoked: 0 } });
  });

  test('a failed revoke-others rejects, reports one Error with operation session.revoke-others, keeps the session', async () => {
    const { h, tokens } = signedIn();
    h.reply(REVOKE_OTHERS, fault('http', 400, { error: { id: 'error.request.invalid', message: 'bad' } }));

    const result = await drive(h.sdk.signOutOtherSessions());

    expect(result.ok).toBe(false);
    expect(errorsOf(h)).toHaveLength(1);
    expect(errorsOf(h)[0]).toMatchObject({ operation: 'session.revoke-others' });
    expectStillSignedIn(h, tokens);
  });
});

describe('revokeSession', () => {
  test('sends DELETE /user/sessions/{id} and resolves to nothing', async () => {
    const { h } = signedIn();

    const result = await drive(h.sdk.revokeSession(OTHER_SID));

    expect(result).toEqual({ ok: true, value: undefined });
    const sent = h.wire(`${SESSIONS}/${OTHER_SID}`);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.method?.toUpperCase()).toBe('DELETE');
  });

  test('URL-encodes the session id in the path', async () => {
    const { h } = signedIn();
    const id = 'sess/with space?x=1#frag';
    const encoded = encodeURIComponent(id);
    h.reply(`${SESSIONS}/${encoded}`, { status: 'ok' });

    const result = await drive(h.sdk.revokeSession(id));

    expect(result.ok).toBe(true);
    const sent = h.wire(`${SESSIONS}/${encoded}`);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.method?.toUpperCase()).toBe('DELETE');
    expect(h.requests.filter((r) => r.url?.includes('/user/sessions/sess/'))).toHaveLength(0);
  });

  test('revoking another session does not sign out', async () => {
    const { h, tokens } = signedIn();

    await drive(h.sdk.revokeSession(OTHER_SID));
    await settle();

    expectStillSignedIn(h, tokens);
    expect(storedTokenStrings(h, tokens)).toContain(tokens.access_token);
    expect(h.navigations).toEqual([]);
  });

  test('revoking the current session (sid of the stored access token) clears stored tokens and emits exactly one SignOut', async () => {
    const { h, tokens } = signedIn(tokensFor({ access: { sid: CURRENT_SID }, id: { sid: CURRENT_SID } }));

    const result = await drive(h.sdk.revokeSession(CURRENT_SID));
    await settle();

    expect(result).toEqual({ ok: true, value: undefined });
    expect(h.wire(`${SESSIONS}/${CURRENT_SID}`)).toHaveLength(1);
    expectSignedOut(h, tokens);
  });

  test('the SignOut comes after the DELETE was answered', async () => {
    const { h } = signedIn();
    let deletesAtSignOut = -1;
    h.sdk.subscribe(
      {
        onAuthChange: () => {
          deletesAtSignOut = h.wire(`${SESSIONS}/${CURRENT_SID}`).length;
        },
      },
      [PassflowEvent.SignOut],
    );

    await drive(h.sdk.revokeSession(CURRENT_SID));

    expect(deletesAtSignOut).toBe(1);
  });

  test('the access token sid decides, even when the ID token names another session', async () => {
    const { h, tokens } = signedIn(tokensFor({ access: { sid: CURRENT_SID }, id: { sid: OTHER_SID } }));

    await drive(h.sdk.revokeSession(OTHER_SID));
    await settle();

    expectStillSignedIn(h, tokens);
  });

  test('revoking the current session signs out via the stored ID token sid when the access token has no sid', async () => {
    const { h, tokens } = signedIn(tokensFor({ id: { sid: CURRENT_SID } }));

    const result = await drive(h.sdk.revokeSession(CURRENT_SID));
    await settle();

    expect(result.ok).toBe(true);
    expectSignedOut(h, tokens);
  });

  test('with no sid on either stored token, revoking a session does not sign out', async () => {
    const { h, tokens } = signedIn(tokensFor());

    await drive(h.sdk.revokeSession(CURRENT_SID));
    await settle();

    expectStillSignedIn(h, tokens);
  });

  test('a failed revoke (404) rejects, reports one Error with operation session.revoke, and does not sign out', async () => {
    const { h, tokens } = signedIn();
    h.reply(
      `${SESSIONS}/${OTHER_SID}`,
      fault('http', 404, { error: { id: 'error.session.not_found', message: 'session not found' } }),
    );

    const result = await drive(h.sdk.revokeSession(OTHER_SID));
    await settle();

    expect(result.ok).toBe(false);
    expect(errorsOf(h)).toHaveLength(1);
    expect(errorsOf(h)[0]).toMatchObject({ operation: 'session.revoke' });
    expectStillSignedIn(h, tokens);
  });

  test('a failed revoke of the current session (404) does not sign out either', async () => {
    const { h, tokens } = signedIn();
    h.reply(
      `${SESSIONS}/${CURRENT_SID}`,
      fault('http', 404, { error: { id: 'error.session.not_found', message: 'session not found' } }),
    );

    const result = await drive(h.sdk.revokeSession(CURRENT_SID));
    await settle();

    expect(result.ok).toBe(false);
    expect(errorsOf(h)).toHaveLength(1);
    expect(errorsOf(h)[0]).toMatchObject({ operation: 'session.revoke' });
    expectStillSignedIn(h, tokens);
    expect(storedTokenStrings(h, tokens)).toContain(tokens.access_token);
  });

  test('revoking the current session still signs out when the server logout call fails', async () => {
    const { h, tokens } = signedIn();
    h.reply(LOGOUT, fault('http', 401, { error: { id: 'error.token.invalid', message: 'session ended' } }));

    const result = await drive(h.sdk.revokeSession(CURRENT_SID));
    await settle();

    expect(result.ok).toBe(true);
    expectSignedOut(h, tokens);
    expect(errorsOf(h).filter((e) => e.operation === 'session.revoke')).toEqual([]);
  });

  test('no call asks for a new token pair while the stored access token is valid', async () => {
    const { h } = signedIn();
    h.reply(SESSIONS, { sessions: SERVER_SESSIONS });
    h.reply(REVOKE_OTHERS, { revoked: 1 });

    await drive(h.sdk.listSessions());
    await drive(h.sdk.signOutOtherSessions());
    await drive(h.sdk.revokeSession(OTHER_SID));

    expect(h.wire(REFRESH)).toHaveLength(0);
  });
});

describe('revoking the current session after a hosted sign-in', () => {
  test('ends the hosted session like logOut: one SignOut, then the end-session navigation', async () => {
    const h = modeHarness(SIMPLE_APP);
    h.reply(LOGOUT, { status: 'ok' });
    const tokens = await issuedTokens(await publishKey(h), { sid: CURRENT_SID });
    h.reply(`${SESSIONS}/${CURRENT_SID}`, { status: 'ok' });
    h.land(`${PAGE}?keep=1#${tokenParams(tokens)}`);
    const c = h.client({ parseQueryParams: true });
    await until(() => c.of(PassflowEvent.SignIn).length + c.of(PassflowEvent.Error).length > 0);
    await settle();
    expect(c.sdk.isAuthenticated()).toBe(true);
    const before = h.navigations.length;

    const result = await drive(c.sdk.revokeSession(CURRENT_SID));
    await settle();

    expect(result.ok).toBe(true);
    expect(c.of(PassflowEvent.SignOut)).toHaveLength(1);
    expect(c.sdk.isAuthenticated()).toBe(false);
    const sent = h.navigations.slice(before);
    expect(sent).toHaveLength(1);
    const url = new URL(sent[0]!);
    expect(url.origin + url.pathname).toBe(END_SESSION);
    expect(url.searchParams.get('id_token_hint')).toBe(tokens.id_token);
  });
});

describe('exported session types', () => {
  test('match the public contract', () => {
    expectTypeOf<PassflowUserSessionList>().toEqualTypeOf<{ sessions: PassflowUserSession[] }>();
    expectTypeOf<PassflowRevokeOtherSessionsResponse>().toEqualTypeOf<{ revoked: number }>();
    expectTypeOf<PassflowUserSession['id']>().toEqualTypeOf<string>();
    expectTypeOf<PassflowUserSession['app_id']>().toEqualTypeOf<string>();
    expectTypeOf<PassflowUserSession['current']>().toEqualTypeOf<boolean>();
    expectTypeOf<PassflowUserSession['device']>().toEqualTypeOf<PassflowSessionDevice | undefined>();
    expectTypeOf<PassflowSessionDevice['type']>().toEqualTypeOf<string | undefined>();
    expectTypeOf<Passflow['listSessions']>().returns.toEqualTypeOf<Promise<PassflowUserSession[]>>();
    expectTypeOf<Passflow['revokeSession']>().parameters.toEqualTypeOf<[sessionId: string]>();
    expectTypeOf<Passflow['revokeSession']>().returns.toEqualTypeOf<Promise<void>>();
    expectTypeOf<Passflow['signOutOtherSessions']>().returns.toEqualTypeOf<Promise<PassflowRevokeOtherSessionsResponse>>();
  });
});
