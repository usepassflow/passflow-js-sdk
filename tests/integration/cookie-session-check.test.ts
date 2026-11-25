import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AxiosClient } from '../../lib/api/axios-client';
import { PassflowError } from '../../lib/api/model';
import { Passflow } from '../../lib/passflow';
import { StorageManager } from '../../lib/storage';
import { PassflowEvent } from '../../lib/store';
import { TokenDeliveryMode } from '../../lib/types';
import { TEST_CONFIG } from '../helpers/fixtures';

const b64 = (value: unknown): string => btoa(JSON.stringify(value)).replace(/=+$/, '');
const ID_TOKEN = `${b64({ alg: 'none' })}.${b64({ aud: [TEST_CONFIG.appId], sub: 'user-1', exp: 4102444800 })}.sig`;
const SESSION_KEY = `passflow_session_state:${TEST_CONFIG.appId}`;

// GET /user/me answers 200 with the user itself.
const USER = { id: 'user-1', email: 'user@example.com', username: 'user', email_verified: true };

describe('the cookie-mode session check on load', () => {
  // What a cookie-mode sign-in leaves in storage; the session state is not stored yet.
  const storeCookieSession = () => {
    const storage = new StorageManager({ storage: localStorage, appId: TEST_CONFIG.appId });
    storage.setDeliveryMode(TokenDeliveryMode.Cookie);
    storage.saveTokens({ id_token: ID_TOKEN }, TokenDeliveryMode.Cookie);
    storage.setCsrfToken('csrf-1');
  };
  const answerUserMe = (answer: () => Promise<unknown>) =>
    vi
      .spyOn(AxiosClient.prototype, 'get')
      .mockImplementation(((path: string) => (path === '/user/me' ? answer() : Promise.resolve({}))) as never);

  beforeEach(() => {
    localStorage.clear();
    storeCookieSession();
  });
  afterEach(() => vi.restoreAllMocks());

  test('a 200 with the user keeps the session valid and reports the user', async () => {
    answerUserMe(() => Promise.resolve(USER));
    const sdk = new Passflow(TEST_CONFIG);
    const restored: unknown[] = [];
    sdk.subscribe({ onAuthChange: (event, payload) => event === PassflowEvent.SessionRestored && restored.push(payload) });

    expect(await sdk.restoreSession()).toBe(true);

    expect(localStorage.getItem(SESSION_KEY)).toBe('valid');
    expect(sdk.isAuthenticated()).toBe(true);
    expect(restored).toContainEqual(USER);
  });

  test.each([
    ['an HTML page', '<!doctype html><title>Sign in</title>'],
    ['an object with no id', { status: 'ok' }],
    ['an empty body', ''],
  ])('a 200 that is not the user (%s) marks the session invalid', async (_name, body) => {
    answerUserMe(() => Promise.resolve(body));
    const sdk = new Passflow(TEST_CONFIG);

    expect(await sdk.restoreSession()).toBe(false);

    expect(localStorage.getItem(SESSION_KEY)).toBe('invalid');
    expect(sdk.isAuthenticated()).toBe(false);
  });

  test('a 401 marks the session invalid', async () => {
    answerUserMe(() =>
      Promise.reject(
        new PassflowError({ id: 'error.unauthorized', message: 'Unauthorized', status: 401, location: '', time: '' }),
      ),
    );
    const sdk = new Passflow(TEST_CONFIG);

    expect(await sdk.restoreSession()).toBe(false);

    expect(localStorage.getItem(SESSION_KEY)).toBe('invalid');
    expect(sdk.isAuthenticated()).toBe(false);
  });

  test('a network failure marks the session invalid', async () => {
    answerUserMe(() => Promise.reject(new Error('Network Error')));
    const sdk = new Passflow(TEST_CONFIG);

    expect(await sdk.restoreSession()).toBe(false);

    expect(localStorage.getItem(SESSION_KEY)).toBe('invalid');
    expect(sdk.isAuthenticated()).toBe(false);
  });
});
