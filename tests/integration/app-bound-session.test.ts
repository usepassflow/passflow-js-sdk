import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AuthAPI } from '../../lib/api';
import { Passflow } from '../../lib/passflow';
import { StorageManager } from '../../lib/storage';
import { SessionState, TokenDeliveryManager } from '../../lib/token/delivery-manager';
import { TokenDeliveryMode } from '../../lib/types';
import { TEST_CONFIG, VALID_TOKENS } from '../helpers/fixtures';

const b64 = (value: unknown): string => btoa(JSON.stringify(value)).replace(/=+$/, '');
const idTokenFor = (aud: string): string =>
  `${b64({ alg: 'none' })}.${b64({ aud: [aud], sub: 'user-b', exp: 4102444800 })}.sig`;

describe("another app's session on the same origin", () => {
  beforeEach(() => localStorage.clear());

  test('does not count as signed in when only the app id changes', () => {
    const first = new Passflow(TEST_CONFIG);
    first.setTokens(VALID_TOKENS);
    expect(first.isAuthenticated()).toBe(true);

    const other = new Passflow({ ...TEST_CONFIG, appId: 'another-app' });
    expect(other.isAuthenticated()).toBe(false);
    expect(other.getParsedTokens()).toBeUndefined();
  });

  test("logOut on another app's instance leaves the first app signed in", async () => {
    const first = new Passflow(TEST_CONFIG);
    first.setTokens(VALID_TOKENS);

    const other = new Passflow({ ...TEST_CONFIG, appId: 'another-app' });
    await other.logOut();

    const again = new Passflow(TEST_CONFIG);
    expect(again.isAuthenticated()).toBe(true);
    expect((await again.getTokens())?.access_token).toBe(VALID_TOKENS.access_token);
  });

  test("apps split by keyStoragePrefix: A's logOut signs A out while B's cookie-mode session stays", async () => {
    const b = new StorageManager({ storage: localStorage, prefix: 'b', appId: 'app-b' });
    const bId = idTokenFor('app-b');
    b.setIdToken(bId);

    const a = new Passflow({ ...TEST_CONFIG, keyStoragePrefix: 'a' });
    a.setTokens(VALID_TOKENS);
    await a.logOut();

    expect(new Passflow({ ...TEST_CONFIG, keyStoragePrefix: 'a' }).isAuthenticated()).toBe(false);
    expect(new StorageManager({ storage: localStorage, prefix: 'b', appId: 'app-b' }).getIdToken()).toBe(bId);
  });

  test("mixed keys: A's logOut signs A out while B's id token stays", async () => {
    const bId = idTokenFor('app-b');
    localStorage.setItem('id_token', bId);

    const a = new Passflow(TEST_CONFIG);
    a.setTokens({ access_token: VALID_TOKENS.access_token, refresh_token: VALID_TOKENS.refresh_token });
    await a.logOut();

    expect(new Passflow(TEST_CONFIG).isAuthenticated()).toBe(false);
    expect(localStorage.getItem('access')).toBeNull();
    expect(localStorage.getItem('id_token')).toBe(bId);
  });

  const storeCookieSessionOfB = () => {
    const b = new StorageManager({ storage: localStorage, appId: 'app-b' });
    b.setDeliveryMode(TokenDeliveryMode.Cookie);
    b.saveTokens({ id_token: idTokenFor('app-b') }, TokenDeliveryMode.Cookie);
    b.setCsrfToken('csrf-b');
    localStorage.setItem('passflow_session_state:app-b', 'valid');
    return b;
  };

  test("A's logOut leaves B's cookie-mode session signed in", async () => {
    // Only app B's cookie-mode session is stored; app A (TEST_CONFIG) holds nothing.
    const b = storeCookieSessionOfB();

    await new Passflow(TEST_CONFIG).logOut();

    expect(b.getIdToken()).toBeDefined();
    expect(b.getCsrfToken()).toBe('csrf-b');
    expect(b.getDeliveryMode()).toBe(TokenDeliveryMode.Cookie);
    expect(localStorage.getItem('passflow_session_state:app-b')).toBe('valid');
  });

  test("an instance created while only B's cookie-mode session is stored leaves B's session state alone", async () => {
    storeCookieSessionOfB();

    const a = new Passflow(TEST_CONFIG);
    await a.restoreSession();

    expect(localStorage.getItem('passflow_session_state:app-b')).toBe('valid');
  });

  test('setAppId to another app drops the session the instance holds', async () => {
    const sdk = new Passflow(TEST_CONFIG);
    sdk.setTokens(VALID_TOKENS);
    sdk.setAppId('another-app');
    expect(await sdk.getTokens()).toBeUndefined();
    expect(sdk.isAuthenticated()).toBe(false);
  });
});

describe('the delivery mode, CSRF token and cookie-mode id token of two apps on one storage', () => {
  const KEYS = ['passflow_delivery_mode', 'passflow_csrf_token', 'passflow_id_token'];
  const keysOf = (appId: string) => Object.fromEntries(KEYS.map((key) => [key, localStorage.getItem(`${key}:${appId}`)]));
  const modeOf = (sdk: Passflow) =>
    (
      sdk as unknown as { authService: { tokenDeliveryManager: TokenDeliveryManager } }
    ).authService.tokenDeliveryManager.getMode();

  // What a cookie-mode sign-in of `appId` leaves in storage.
  const storeCookieSession = (appId: string) => {
    const storage = new StorageManager({ storage: localStorage, appId });
    storage.setDeliveryMode(TokenDeliveryMode.Cookie);
    storage.setIdToken(idTokenFor(appId));
    storage.setCsrfToken(`csrf-${appId}`);
    return keysOf(appId);
  };

  beforeEach(() => {
    localStorage.clear();
    vi.spyOn(AuthAPI.prototype, 'logOut').mockResolvedValue({ status: 'ok' } as never);
    // The cookie-mode check on load stays unanswered: these tests are about the stored keys.
    vi.spyOn(AuthAPI.prototype, 'validateSession').mockReturnValue(new Promise(() => {}));
  });
  afterEach(() => vi.restoreAllMocks());

  test('each value is stored under the key of its app', () => {
    const stored = storeCookieSession('app-b');

    expect(stored).toEqual({
      passflow_delivery_mode: 'cookie',
      passflow_csrf_token: 'csrf-app-b',
      passflow_id_token: idTokenFor('app-b'),
    });
    for (const key of KEYS) expect(localStorage.getItem(key)).toBeNull();
  });

  test("a JSON-token app constructed beside B's cookie-mode session stays in JSON mode and leaves B's keys", () => {
    const stored = storeCookieSession('app-b');

    const a = new Passflow(TEST_CONFIG);
    a.setTokens(VALID_TOKENS);

    expect(modeOf(a)).toBe(TokenDeliveryMode.JsonBody);
    expect(a.isAuthenticated()).toBe(true);
    expect(localStorage.getItem('access')).toBe(VALID_TOKENS.access_token);
    expect(keysOf('app-b')).toEqual(stored);
  });

  test("a JSON-token app's sign-out leaves B's cookie-mode keys", async () => {
    const stored = storeCookieSession('app-b');
    const a = new Passflow(TEST_CONFIG);
    a.setTokens(VALID_TOKENS);

    await a.logOut();

    expect(a.isAuthenticated()).toBe(false);
    expect(keysOf('app-b')).toEqual(stored);
    expect(new Passflow({ ...TEST_CONFIG, appId: 'app-b' }).isAuthenticated()).toBe(true);
  });

  test("two cookie-mode apps: A's sign-out removes A's keys and leaves B's", async () => {
    storeCookieSession('app-a');
    const stored = storeCookieSession('app-b');
    const a = new Passflow({ ...TEST_CONFIG, appId: 'app-a' });
    expect(a.isAuthenticated()).toBe(true);

    await a.logOut();

    expect(keysOf('app-a')).toEqual({ passflow_delivery_mode: null, passflow_csrf_token: null, passflow_id_token: null });
    expect(keysOf('app-b')).toEqual(stored);
    expect(new Passflow({ ...TEST_CONFIG, appId: 'app-b' }).isAuthenticated()).toBe(true);
  });

  test('an app with an app id does not read values stored under the plain keys', () => {
    const plain = new StorageManager({ storage: localStorage });
    plain.setDeliveryMode(TokenDeliveryMode.Cookie);
    plain.setIdToken(idTokenFor('app-a'));
    plain.setCsrfToken('csrf-plain');

    const a = new Passflow({ ...TEST_CONFIG, appId: 'app-a' });

    expect(modeOf(a)).toBe(TokenDeliveryMode.JsonBody);
    expect(a.isAuthenticated()).toBe(false);
    expect(new StorageManager({ storage: localStorage, appId: 'app-a' }).getCsrfToken()).toBeUndefined();
  });

  test('with no app id the values are stored under the plain keys', () => {
    const plain = new StorageManager({ storage: localStorage });
    plain.setDeliveryMode(TokenDeliveryMode.Cookie);
    plain.setIdToken(idTokenFor('app-a'));
    plain.setCsrfToken('csrf-plain');

    expect(localStorage.getItem('passflow_delivery_mode')).toBe('cookie');
    expect(localStorage.getItem('passflow_id_token')).toBe(idTokenFor('app-a'));
    expect(localStorage.getItem('passflow_csrf_token')).toBe('csrf-plain');
  });

  test("setAppId to B loads B's stored delivery mode", () => {
    storeCookieSession('app-b');
    const sdk = new Passflow(TEST_CONFIG);
    expect(modeOf(sdk)).toBe(TokenDeliveryMode.JsonBody);

    sdk.setAppId('app-b');

    expect(modeOf(sdk)).toBe(TokenDeliveryMode.Cookie);
    expect(sdk.isAuthenticated()).toBe(true);
  });

  test("setAppId to B loads B's stored tokens into the token cache", () => {
    const stored = storeCookieSession('app-b');
    const sdk = new Passflow(TEST_CONFIG);
    expect(sdk.getCachedTokens()).toBeUndefined();

    sdk.setAppId('app-b');

    expect(sdk.getCachedTokens()).toEqual({ id_token: stored.passflow_id_token });
  });

  test('setAppId to an app with nothing stored empties the token cache', () => {
    const sdk = new Passflow(TEST_CONFIG);
    sdk.setTokens(VALID_TOKENS);
    expect(sdk.getCachedTokens()?.access_token).toBe(VALID_TOKENS.access_token);

    sdk.setAppId('another-app');

    expect(sdk.getCachedTokens()).toBeUndefined();
    expect(localStorage.getItem('access')).toBe(VALID_TOKENS.access_token);
  });

  test("setAppId to B puts the HTTP client in B's delivery mode", () => {
    storeCookieSession('app-b');
    const sdk = new Passflow(TEST_CONFIG);
    const client = (sdk as unknown as { authApi: { axiosClient: { tokenDeliveryManager: TokenDeliveryManager } } }).authApi
      .axiosClient;
    expect(client.tokenDeliveryManager.isCookieMode()).toBe(false);

    sdk.setAppId('app-b');

    expect(client.tokenDeliveryManager.isCookieMode()).toBe(true);
  });
});

describe('the session state of two apps on the same origin', () => {
  const BFF = { tokenExchange: { enabled: true, callbackUrl: 'https://app.example.com/api/auth/callback' } };
  const open = (appId: string) => new Passflow({ ...TEST_CONFIG, appId, ...BFF });
  const sessionOf = (sdk: Passflow) =>
    (sdk as unknown as { authService: { tokenDeliveryManager: TokenDeliveryManager } }).authService.tokenDeliveryManager;

  // What a BFF sign-in leaves behind: the app's id token and a valid session.
  const signIn = (sdk: Passflow, appId: string) => {
    new StorageManager({ storage: localStorage, appId }).setIdToken(idTokenFor(appId));
    sessionOf(sdk).setSessionValid();
  };

  beforeEach(() => {
    localStorage.clear();
    vi.spyOn(AuthAPI.prototype, 'logOut').mockResolvedValue({ status: 'ok' } as never);
  });
  afterEach(() => vi.restoreAllMocks());

  test("A's logOut leaves B's session state valid", async () => {
    const a = open('app-a');
    const b = open('app-b');
    signIn(b, 'app-b');
    signIn(a, 'app-a');

    await a.logOut();

    expect(sessionOf(a).getSessionState()).toBe(SessionState.Unknown);
    expect(sessionOf(open('app-b')).getSessionState()).toBe(SessionState.Valid);
  });

  test("A's logOut removes A's stored state and leaves B's", async () => {
    const a = open('app-a');
    const b = open('app-b');
    signIn(a, 'app-a');
    signIn(b, 'app-b');

    await a.logOut();

    expect(localStorage.getItem('passflow_session_state:app-a')).toBeNull();
    expect(localStorage.getItem('passflow_session_state:app-b')).toBe('valid');
  });

  test("A's session marked invalid leaves B signed in", () => {
    const a = open('app-a');
    const b = open('app-b');
    signIn(a, 'app-a');
    signIn(b, 'app-b');

    sessionOf(a).setSessionInvalid();

    const again = open('app-b');
    expect(sessionOf(again).getSessionState()).toBe(SessionState.Valid);
    expect(again.isAuthenticated()).toBe(true);
  });

  test("setAppId to B loads B's stored state and leaves A's", () => {
    const a = open('app-a');
    signIn(a, 'app-a');
    sessionOf(open('app-b')).setSessionInvalid();

    a.setAppId('app-b');

    expect(sessionOf(a).getSessionState()).toBe(SessionState.Invalid);
    expect(localStorage.getItem('passflow_session_state:app-a')).toBe('valid');
  });

  test('with no app id the state is stored under the plain key', () => {
    const manager = new TokenDeliveryManager(new StorageManager({ storage: localStorage }));

    manager.setSessionValid();
    expect(localStorage.getItem('passflow_session_state')).toBe('valid');

    manager.setSessionInvalid();
    expect(localStorage.getItem('passflow_session_state')).toBe('invalid');
    expect(new TokenDeliveryManager(new StorageManager({ storage: localStorage })).getSessionState()).toBe(
      SessionState.Invalid,
    );
  });
});
