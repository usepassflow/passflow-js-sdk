import { beforeEach, describe, expect, test } from 'vitest';
import { Passflow } from '../../lib/passflow';
import { StorageManager } from '../../lib/storage';
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

  test('setAppId to another app drops the session the instance holds', async () => {
    const sdk = new Passflow(TEST_CONFIG);
    sdk.setTokens(VALID_TOKENS);
    sdk.setAppId('another-app');
    expect(await sdk.getTokens()).toBeUndefined();
    expect(sdk.isAuthenticated()).toBe(false);
  });
});
