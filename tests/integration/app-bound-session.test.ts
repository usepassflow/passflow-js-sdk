import { beforeEach, describe, expect, test } from 'vitest';
import { Passflow } from '../../lib/passflow';
import { StorageManager } from '../../lib/storage';
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

  test('a prefixed app signs out although another app wrote the shared cookie-mode id token after its sign-in', async () => {
    const a = new Passflow({ ...TEST_CONFIG, keyStoragePrefix: 'a' });
    a.setTokens(VALID_TOKENS);
    expect(a.isAuthenticated()).toBe(true);
    localStorage.setItem('passflow_id_token', idTokenFor('another-app'));

    await a.logOut();

    expect(new Passflow({ ...TEST_CONFIG, keyStoragePrefix: 'a' }).isAuthenticated()).toBe(false);
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
    localStorage.setItem('passflow_session_state', 'valid');
    return b;
  };

  test("A's logOut leaves B's cookie-mode session signed in", async () => {
    // Only app B's cookie-mode session is stored; app A (TEST_CONFIG) holds nothing.
    const b = storeCookieSessionOfB();

    await new Passflow(TEST_CONFIG).logOut();

    expect(b.getIdToken()).toBeDefined();
    expect(b.getCsrfToken()).toBe('csrf-b');
    expect(b.getDeliveryMode()).toBe(TokenDeliveryMode.Cookie);
    expect(localStorage.getItem('passflow_session_state')).toBe('valid');
  });

  test("an instance created while only B's cookie-mode session is stored leaves B's session state alone", async () => {
    storeCookieSessionOfB();

    const a = new Passflow(TEST_CONFIG);
    await a.restoreSession();

    expect(localStorage.getItem('passflow_session_state')).toBe('valid');
  });

  test('setAppId to another app drops the session the instance holds', async () => {
    const sdk = new Passflow(TEST_CONFIG);
    sdk.setTokens(VALID_TOKENS);
    sdk.setAppId('another-app');
    expect(await sdk.getTokens()).toBeUndefined();
    expect(sdk.isAuthenticated()).toBe(false);
  });
});
