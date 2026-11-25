/**
 * `setAppId()` while a request about the previous app's session is still unanswered: the late
 * answer changes nothing for the new app.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AuthAPI } from '../../lib/api';
import { Passflow } from '../../lib/passflow';
import { UpgradeCommitInterruptedError } from '../../lib/refresh/errors';
import { StorageManager } from '../../lib/storage';
import { TokenDeliveryMode } from '../../lib/token/delivery-manager';
import type { Tokens } from '../../lib/types';
import { TEST_CONFIG, VALID_TOKENS } from '../helpers/fixtures';
import { jwt } from '../refresh/jwt';

const KEYS = ['passflow_id_token', 'passflow_csrf_token', 'passflow_delivery_mode', 'passflow_session_state'];
const storedFor = (appId: string) => KEYS.map((key) => localStorage.getItem(`${key}:${appId}`));
const NOTHING = [null, null, null, null];

const idTokenOf = (appId: string, jti: string) =>
  jwt({ sub: 'user-1', aud: [appId], exp: 4_102_444_800, iat: 1_700_000_000, jti, type: 'id' });

/** A promise settled from outside, to hold an API answer back. */
const held = <T>() => {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

const refreshOf = (sdk: Passflow) =>
  (sdk as unknown as { authService: { refreshToken: () => Promise<unknown> } }).authService.refreshToken();

/** Lets the settled answer run through every continuation. */
const settle = async () => {
  for (let i = 0; i < 20; i += 1) await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
};

describe('setAppId() while a request for the previous app is unanswered', () => {
  let sdk: Passflow | undefined;

  const seedCookieSession = (appId: string) => {
    const storage = new StorageManager({ storage: localStorage, appId });
    storage.setDeliveryMode(TokenDeliveryMode.Cookie);
    storage.setIdToken(idTokenOf(appId, 'id-1'));
    storage.setCsrfToken('csrf-1');
  };

  beforeEach(() => localStorage.clear());
  afterEach(() => {
    sdk?.dispose();
    sdk = undefined;
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  test("cookie mode: a refresh answer for A that arrives after setAppId('app-b') stores nothing for B", async () => {
    seedCookieSession('app-a');
    vi.spyOn(AuthAPI.prototype, 'validateSession').mockResolvedValue({ id: 'user-1' });
    const answer = held<unknown>();
    const refreshToken = vi.spyOn(AuthAPI.prototype, 'refreshToken').mockReturnValue(answer.promise as never);
    const instance = new Passflow({ ...TEST_CONFIG, appId: 'app-a', refreshCoordination: 'none' });
    sdk = instance;
    await settle();
    expect(instance.isAuthenticated()).toBe(true);

    const refresh = refreshOf(instance).catch(() => undefined);
    await vi.waitFor(() => expect(refreshToken).toHaveBeenCalledTimes(1));
    instance.setAppId('app-b');
    answer.resolve({ id_token: idTokenOf('app-a', 'id-2'), csrf_token: 'csrf-2', token_delivery: 'cookie' });
    await refresh;
    await settle();

    expect(storedFor('app-b')).toEqual(NOTHING);
    expect(instance.getCachedTokens()).toBeUndefined();
    expect(instance.isAuthenticated()).toBe(false);
  });

  test("JSON mode: a refresh answer for A that arrives after setAppId('app-b') gives B no tokens", async () => {
    const answer = held<Tokens>();
    const refreshToken = vi.spyOn(AuthAPI.prototype, 'refreshToken').mockReturnValue(answer.promise as never);
    const instance = new Passflow({ ...TEST_CONFIG, refreshCoordination: 'none' });
    sdk = instance;
    instance.setTokens(VALID_TOKENS);

    const refresh = instance.refreshToken().catch(() => undefined);
    await vi.waitFor(() => expect(refreshToken).toHaveBeenCalledTimes(1));
    instance.setAppId('app-b');
    answer.resolve({ ...VALID_TOKENS });
    await refresh;
    await settle();

    expect(storedFor('app-b')).toEqual(NOTHING);
    expect(instance.getCachedTokens()).toBeUndefined();
    expect(await instance.getTokens()).toBeUndefined();
    expect(instance.isAuthenticated()).toBe(false);
  });

  test.each([
    ['a valid answer', (answer: ReturnType<typeof held<{ id: string }>>) => answer.resolve({ id: 'user-1' })],
    ['a refusal', (answer: ReturnType<typeof held<{ id: string }>>) => answer.reject(new Error('unauthorized'))],
  ])(
    "the session check on load for A answered after setAppId('app-b') (%s) leaves B's session state alone",
    async (_name, release) => {
      seedCookieSession('app-a');
      const answer = held<{ id: string }>();
      const validateSession = vi.spyOn(AuthAPI.prototype, 'validateSession').mockReturnValue(answer.promise);
      const instance = new Passflow({ ...TEST_CONFIG, appId: 'app-a', refreshCoordination: 'none' });
      sdk = instance;
      await vi.waitFor(() => expect(validateSession).toHaveBeenCalledTimes(1));

      instance.setAppId('app-b');
      release(answer);
      await settle();

      expect(storedFor('app-b')).toEqual(NOTHING);
    },
  );
  test("cookie mode: a sign-in answer for A that arrives after setAppId('app-b') is refused and stores nothing for B", async () => {
    const answer = held<unknown>();
    vi.spyOn(AuthAPI.prototype, 'signIn').mockReturnValue(answer.promise as never);
    const instance = new Passflow({ ...TEST_CONFIG, appId: 'app-a', refreshCoordination: 'none' });
    sdk = instance;
    (instance as unknown as { appSettingsRead: unknown }).appSettingsRead = Promise.resolve(undefined);

    const signIn = instance.signIn({ email: 'user@example.com', password: 'Password1!' });
    const outcome = signIn.then(
      () => 'resolved',
      () => 'rejected',
    );
    await vi.waitFor(() => expect(AuthAPI.prototype.signIn).toHaveBeenCalledTimes(1));
    instance.setAppId('app-b');
    answer.resolve({ id_token: idTokenOf('app-a', 'id-2'), csrf_token: 'csrf-2', token_delivery: 'cookie' });

    expect(await outcome).toBe('rejected');
    expect(storedFor('app-b')).toEqual(NOTHING);
    expect(instance.getCachedTokens()).toBeUndefined();
    expect(instance.isAuthenticated()).toBe(false);
  });

  test("cookie mode: an upgrade commit for A answered after setAppId('app-b') rejects and stores nothing for B", async () => {
    seedCookieSession('app-a');
    vi.spyOn(AuthAPI.prototype, 'validateSession').mockResolvedValue({ id: 'user-1' });
    const answer = held<unknown>();
    const refreshToken = vi.spyOn(AuthAPI.prototype, 'refreshToken').mockReturnValue(answer.promise as never);
    const instance = new Passflow({ ...TEST_CONFIG, appId: 'app-a', refreshCoordination: 'none' });
    sdk = instance;
    await settle();
    const controller = (
      instance as unknown as { authService: { refresh: { commitUpgrade: (upgrade: unknown) => Promise<unknown> } } }
    ).authService.refresh;

    const commit = controller.commitUpgrade({ challenge_id: 'c', code: '123456' }).catch((error: unknown) => error);
    await vi.waitFor(() => expect(refreshToken).toHaveBeenCalledTimes(1));
    instance.setAppId('app-b');
    answer.resolve({ id_token: idTokenOf('app-a', 'id-2'), csrf_token: 'csrf-2', token_delivery: 'cookie' });

    expect(await commit).toBeInstanceOf(UpgradeCommitInterruptedError);
    expect(storedFor('app-b')).toEqual(NOTHING);
    expect(instance.isAuthenticated()).toBe(false);
  });

  describe('BFF mode', () => {
    const BFF = { enabled: true, callbackUrl: '/bff/callback', statusUrl: '/bff/status' };
    const status = (authenticated: boolean) =>
      ({ ok: true, status: 200, json: async () => ({ authenticated }) }) as unknown as Response;

    test.each([
      ['a signed-in answer', (answer: ReturnType<typeof held<Response>>) => answer.resolve(status(true))],
      ['a network error', (answer: ReturnType<typeof held<Response>>) => answer.reject(new TypeError('offline'))],
    ])(
      "the session check on load for A answered after setAppId('app-b') (%s) leaves B's session state alone",
      async (_name, release) => {
        const first = held<Response>();
        const fetch = vi
          .fn()
          .mockReturnValueOnce(first.promise)
          .mockReturnValue(new Promise<Response>(() => undefined));
        vi.stubGlobal('fetch', fetch);
        const instance = new Passflow({ ...TEST_CONFIG, appId: 'app-a', tokenExchange: BFF, refreshCoordination: 'none' });
        sdk = instance;
        await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));

        instance.setAppId('app-b');
        release(first);
        await settle();

        expect(localStorage.getItem('passflow_session_state:app-b')).toBeNull();
      },
    );

    test('an instance built without an app id checks the session again for the app id it is given', async () => {
      const first = held<Response>();
      const fetch = vi.fn().mockReturnValueOnce(first.promise).mockResolvedValue(status(true));
      vi.stubGlobal('fetch', fetch);
      const instance = new Passflow({ ...TEST_CONFIG, appId: undefined, tokenExchange: BFF, refreshCoordination: 'none' });
      sdk = instance;
      await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));

      instance.setAppId('app-x');
      first.resolve(status(true));
      await settle();

      expect(fetch).toHaveBeenCalledTimes(2);
      expect(localStorage.getItem('passflow_session_state:app-x')).toBe('valid');
    });
  });
});
