import { describe, expect, test } from 'vitest';
import { StorageManager } from '../../lib/storage/index';
import { TokenType } from '../../lib/token/token';
import { TokenDeliveryMode } from '../../lib/types';
import { FakeStorage } from './fake-storage';

const b64 = (value: unknown): string => btoa(JSON.stringify(value)).replace(/=+$/, '');
const jwt = (claims: Record<string, unknown>): string => `${b64({ alg: 'none' })}.${b64(claims)}.sig`;
const tokenFor = (aud: string[] | string, type: string): string =>
  jwt({ aud, type, sub: 'user-1', exp: Math.floor(Date.now() / 1000) + 3600, iat: 1 });

const tokensFor = (aud: string[] | string) => ({
  access_token: tokenFor(aud, 'access'),
  refresh_token: tokenFor(aud, 'refresh'),
  id_token: tokenFor(aud, 'id'),
  scopes: ['id'],
});

describe('stored tokens are bound to the app', () => {
  test("another app's stored tokens read as absent", () => {
    const storage = new FakeStorage();
    new StorageManager({ storage }).saveTokens(tokensFor(['app-a']));

    const manager = new StorageManager({ storage, appId: 'app-b' });
    expect(manager.getTokens()).toBeUndefined();
    expect(manager.getToken(TokenType.access_token)).toBeUndefined();
    expect(manager.getToken(TokenType.refresh_token)).toBeUndefined();
    expect(manager.getToken(TokenType.id_token)).toBeUndefined();
    expect(manager.hasJsonModeTokens()).toBe(false);
  });

  test("this app's stored tokens are read as before", () => {
    const storage = new FakeStorage();
    const tokens = tokensFor(['app-a']);
    const manager = new StorageManager({ storage, appId: 'app-a' });
    manager.saveTokens(tokens);
    expect(manager.getTokens()).toEqual(tokens);
    expect(manager.getToken(TokenType.refresh_token)).toBe(tokens.refresh_token);
  });

  test('a string aud is accepted too', () => {
    const storage = new FakeStorage();
    const manager = new StorageManager({ storage, appId: 'app-a' });
    manager.saveTokens(tokensFor('app-a'));
    expect(manager.getTokens()?.access_token).toBeDefined();
  });

  test('the cookie-mode id token of another app reads as absent', () => {
    const storage = new FakeStorage();
    new StorageManager({ storage }).saveTokens(tokensFor(['app-a']), TokenDeliveryMode.Cookie);
    storage.setItem('passflow_delivery_mode', TokenDeliveryMode.Cookie);

    const manager = new StorageManager({ storage, appId: 'app-b' });
    expect(manager.getIdToken()).toBeUndefined();
    expect(manager.hasCookieModeIdToken()).toBe(false);
    expect(manager.getTokens()).toBeUndefined();
  });

  test('setAppId switches the app the tokens must belong to', () => {
    const storage = new FakeStorage();
    const manager = new StorageManager({ storage, appId: 'app-b' });
    manager.saveTokens(tokensFor(['app-a']));
    expect(manager.getTokens()).toBeUndefined();
    manager.setAppId('app-a');
    expect(manager.getTokens()?.access_token).toBeDefined();
  });

  test('with no app id every stored token counts', () => {
    const storage = new FakeStorage();
    const manager = new StorageManager({ storage });
    manager.saveTokens(tokensFor(['app-a']));
    expect(manager.getTokens()?.access_token).toBeDefined();
  });

  test('a JWT with no audience counts, since it names no other app', () => {
    const storage = new FakeStorage();
    const manager = new StorageManager({ storage, appId: 'app-a' });
    const access = jwt({ sub: 'user-1', type: 'access' });
    manager.saveTokens({ access_token: access });
    expect(manager.getTokens()?.access_token).toBe(access);
  });

  test('a token that is not a JWT is left to the token checks', () => {
    const storage = new FakeStorage();
    const manager = new StorageManager({ storage, appId: 'app-a' });
    manager.saveTokens({ access_token: 'opaque', refresh_token: 'opaque-refresh' });
    expect(manager.getTokens()?.access_token).toBe('opaque');
  });
});

describe("clearing never removes another app's session", () => {
  test("deleteTokens on app B leaves app A's JSON session in place", () => {
    const storage = new FakeStorage();
    const a = new StorageManager({ storage, appId: 'app-a' });
    const tokens = tokensFor(['app-a']);
    a.saveTokens(tokens);
    a.setHostedSignIn('https://a.example/cb');

    const b = new StorageManager({ storage, appId: 'app-b' });
    b.deleteTokens();
    b.clearIdToken();
    b.clearCsrfToken();

    expect(a.getTokens()).toEqual(tokens);
    expect(a.getHostedSignIn()).toBe('https://a.example/cb');
  });

  test("app B's clearing leaves app A's cookie-mode session in place", () => {
    const storage = new FakeStorage();
    const a = new StorageManager({ storage, appId: 'app-a' });
    a.setDeliveryMode(TokenDeliveryMode.Cookie);
    a.saveTokens(tokensFor(['app-a']), TokenDeliveryMode.Cookie);
    a.setCsrfToken('csrf-a');

    const b = new StorageManager({ storage, appId: 'app-b' });
    b.deleteTokens();
    b.clearIdToken();
    b.clearCsrfToken();

    expect(a.getIdToken()).toBeDefined();
    expect(a.getCsrfToken()).toBe('csrf-a');
    expect(a.getDeliveryMode()).toBe(TokenDeliveryMode.Cookie);
  });

  test("apps split by keyStoragePrefix: A's sign-out clears A's keys while B's cookie-mode ID token stays", () => {
    const storage = new FakeStorage();
    const b = new StorageManager({ storage, prefix: 'b', appId: 'app-b' });
    b.saveTokens(tokensFor(['app-b']), TokenDeliveryMode.Cookie);
    const a = new StorageManager({ storage, prefix: 'a', appId: 'app-a' });
    a.saveTokens(tokensFor(['app-a']));

    a.deleteTokens();

    expect(new StorageManager({ storage, prefix: 'a', appId: 'app-a' }).getTokens()).toBeUndefined();
    expect(new StorageManager({ storage, prefix: 'a', appId: 'app-a' }).hasJsonModeTokens()).toBe(false);
    expect(b.getIdToken()).toBeDefined();
  });

  test("mixed keys: A's sign-out clears A's tokens while B's id token stays", () => {
    const storage = new FakeStorage();
    const b = new StorageManager({ storage, appId: 'app-b' });
    const bTokens = tokensFor(['app-b']);
    b.saveTokens({ id_token: bTokens.id_token });
    const a = new StorageManager({ storage, appId: 'app-a' });
    const aTokens = tokensFor(['app-a']);
    a.saveTokens({ access_token: aTokens.access_token, refresh_token: aTokens.refresh_token, scopes: ['id'] });

    a.deleteTokens();

    expect(storage.getItem('access')).toBeNull();
    expect(storage.getItem('refresh')).toBeNull();
    expect(storage.getItem('tokens_scopes')).toBeNull();
    expect(storage.getItem('id_token')).toBe(bTokens.id_token);
  });

  test("A's sign-out over B's full session clears A's tokens, with B's id token left behind", () => {
    const storage = new FakeStorage();
    new StorageManager({ storage, appId: 'app-b' }).saveTokens(tokensFor(['app-b']));
    const a = new StorageManager({ storage, appId: 'app-a' });
    const own = tokensFor(['app-a']);
    a.saveTokens({ access_token: own.access_token, refresh_token: own.refresh_token, scopes: ['id'] });
    expect(a.getTokens()?.access_token).toBe(own.access_token);

    a.deleteTokens();
    a.clearIdToken();
    a.clearCsrfToken();

    expect(a.getTokens()).toBeUndefined();
  });

  test("this app's session is cleared as before", () => {
    const storage = new FakeStorage();
    const a = new StorageManager({ storage, appId: 'app-a' });
    a.saveTokens(tokensFor(['app-a']));
    a.deleteTokens();
    expect(a.getTokens()).toBeUndefined();
    expect(new StorageManager({ storage }).getTokens()).toBeUndefined();
  });
});

describe('the hosted sign-in record is bound to the app', () => {
  test('another app on the same storage does not see it', () => {
    const storage = new FakeStorage();
    new StorageManager({ storage, appId: 'app-a' }).setHostedSignIn('https://a.example/cb');
    expect(new StorageManager({ storage, appId: 'app-b' }).getHostedSignIn()).toBeUndefined();
    expect(new StorageManager({ storage, appId: 'app-a' }).getHostedSignIn()).toBe('https://a.example/cb');
  });

  test('setAppId switches which record counts', () => {
    const storage = new FakeStorage();
    const manager = new StorageManager({ storage, appId: 'app-a' });
    manager.setHostedSignIn('https://a.example/cb');
    manager.setAppId('app-b');
    expect(manager.getHostedSignIn()).toBeUndefined();
  });
});
