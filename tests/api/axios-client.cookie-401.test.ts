/**
 * A 401 in cookie or BFF mode: one refresh, then the call once more.
 *
 * Real AxiosClient over a real StorageManager; only the HTTP adapter is stubbed. In the first
 * block the refresh handler stands in for the refresh controller; the second runs a real `Passflow`.
 */
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AuthAPI } from '../../lib/api';
import { AxiosClient, type AxiosRefreshHandler, withOwnBearer } from '../../lib/api/axios-client';
import { PassflowError } from '../../lib/api/model';
import { Passflow } from '../../lib/passflow';
import { StorageManager } from '../../lib/storage';
import { TokenDeliveryMode } from '../../lib/token/delivery-manager';
import { TEST_CONFIG } from '../helpers/fixtures';
import { createMockPlatform } from '../helpers/mock-platform';
import { jwt } from '../refresh/jwt';

const memoryStorage = (): Storage => {
  const items = new Map<string, string>();
  return {
    get length() {
      return items.size;
    },
    clear: () => items.clear(),
    key: (index: number) => Array.from(items.keys())[index] ?? null,
    getItem: (key: string) => items.get(key) ?? null,
    setItem: (key: string, value: string) => {
      items.set(key, String(value));
    },
    removeItem: (key: string) => {
      items.delete(key);
    },
  };
};

type Adapter = (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>;

const ok = (config: InternalAxiosRequestConfig): AxiosResponse => ({
  data: { ok: true },
  status: 200,
  statusText: 'OK',
  headers: {},
  config,
});

const unauthorized = (config: InternalAxiosRequestConfig): Promise<AxiosResponse> =>
  Promise.reject(
    new AxiosError('Request failed with status code 401', 'ERR_BAD_REQUEST', config, null, {
      data: {},
      status: 401,
      statusText: '401',
      headers: {},
      config,
    }),
  );

/** 401 for the first `count` requests, 200 after. */
const unauthorizedTimes = (count: number): Adapter => {
  let seen = 0;
  return (config) => {
    seen += 1;
    return seen <= count ? unauthorized(config) : Promise.resolve(ok(config));
  };
};

const idToken = () => jwt({ sub: 'user-1', exp: 4_102_444_800, iat: 1_700_000_000, jti: 'id-1', type: 'id' });

describe('AxiosClient: a 401 in cookie or BFF mode', () => {
  const SESSION_KEY = 'passflow_session_state:app';
  let raw: Storage;
  let storage: StorageManager;
  let sent: InternalAxiosRequestConfig[];
  let handler: ReturnType<typeof vi.fn<AxiosRefreshHandler>>;

  const clientIn = (mode: TokenDeliveryMode | undefined, adapter: Adapter): AxiosClient => {
    if (mode) storage.setDeliveryMode(mode);
    const client = new AxiosClient(
      { url: 'https://api.example.com', appId: 'app', platform: createMockPlatform({ cookiesSupported: () => true }) },
      storage,
    );
    (client as unknown as { instance: { defaults: { adapter: Adapter } } }).instance.defaults.adapter = (config) => {
      sent.push(config);
      return adapter(config);
    };
    client.setRefreshHandler(handler);
    return client;
  };

  beforeEach(() => {
    raw = memoryStorage();
    storage = new StorageManager({ storage: raw, appId: 'app' });
    storage.setIdToken(idToken());
    sent = [];
    handler = vi.fn<AxiosRefreshHandler>().mockResolvedValue({ id_token: idToken() });
  });

  test.each([TokenDeliveryMode.Cookie, TokenDeliveryMode.BFF])(
    '%s mode: one refresh, the call is sent again and succeeds',
    async (mode) => {
      const client = clientIn(mode, unauthorizedTimes(1));

      await expect(client.get('/user/me')).resolves.toEqual({ ok: true });

      expect(handler).toHaveBeenCalledTimes(1);
      expect(handler).toHaveBeenCalledWith({ trigger: 'pre-request', allowStale: false });
      expect(sent).toHaveLength(2);
      expect(raw.getItem(SESSION_KEY)).not.toBe('invalid');
    },
  );

  test('a failed refresh: the call fails with the 401 and the session is invalid', async () => {
    handler.mockRejectedValue(new Error('refresh failed'));
    const client = clientIn(TokenDeliveryMode.Cookie, unauthorizedTimes(1));

    const outcome = await client.get('/user/me').catch((error: unknown) => error);

    expect(outcome).toBeInstanceOf(PassflowError);
    expect((outcome as PassflowError).status).toBe(401);
    expect(sent).toHaveLength(1);
    expect(raw.getItem(SESSION_KEY)).toBe('invalid');
  });

  test('a refresh that ended the session: no second send, the session is invalid', async () => {
    handler.mockResolvedValue(undefined);
    const client = clientIn(TokenDeliveryMode.Cookie, unauthorizedTimes(1));

    await expect(client.get('/user/me')).rejects.toBeInstanceOf(PassflowError);

    expect(sent).toHaveLength(1);
    expect(raw.getItem(SESSION_KEY)).toBe('invalid');
  });

  test('the second send also gets a 401: no further refresh or send, the session is invalid', async () => {
    const client = clientIn(TokenDeliveryMode.Cookie, unauthorizedTimes(5));

    const outcome = await client.get('/user/me').catch((error: unknown) => error);

    expect((outcome as PassflowError).status).toBe(401);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(sent).toHaveLength(2);
    expect(raw.getItem(SESSION_KEY)).toBe('invalid');
  });

  test('the mode set after the client was built counts', async () => {
    const client = clientIn(undefined, unauthorizedTimes(1));
    storage.setDeliveryMode(TokenDeliveryMode.Cookie);

    await expect(client.get('/user/me')).resolves.toEqual({ ok: true });

    expect(handler).toHaveBeenCalledTimes(1);
  });

  test('JSON mode: no refresh, the session is marked invalid', async () => {
    const client = clientIn(undefined, unauthorizedTimes(1));

    await expect(client.get('/user/me')).rejects.toBeInstanceOf(PassflowError);

    expect(handler).not.toHaveBeenCalled();
    expect(sent).toHaveLength(1);
    expect(raw.getItem(SESSION_KEY)).toBe('invalid');
  });

  test('no refresh handler: the call fails and the session is invalid', async () => {
    const client = clientIn(TokenDeliveryMode.Cookie, unauthorizedTimes(1));
    client.setRefreshHandler(undefined);

    await expect(client.get('/user/me')).rejects.toBeInstanceOf(PassflowError);

    expect(sent).toHaveLength(1);
    expect(raw.getItem(SESSION_KEY)).toBe('invalid');
  });

  test.each([
    ['the refresh call', (client: AxiosClient) => client.post('/auth/refresh', {})],
    ['a logout', (client: AxiosClient) => client.post('/user/logout', {})],
    ['a hosted session call', (client: AxiosClient) => client.get('/auth/session/check')],
    ['a sign-in', (client: AxiosClient) => client.post('/auth/login', {})],
    ['a call with its own bearer', (client: AxiosClient) => client.get('/user/me', withOwnBearer('tfa-token'))],
  ])('%s is not refreshed for or sent again', async (_name, call) => {
    const client = clientIn(TokenDeliveryMode.Cookie, unauthorizedTimes(1));

    await expect(call(client)).rejects.toBeInstanceOf(PassflowError);

    expect(handler).not.toHaveBeenCalled();
    expect(sent).toHaveLength(1);
  });
});

describe('Passflow in cookie mode', () => {
  let passflow: Passflow | undefined;

  afterEach(() => {
    passflow?.dispose();
    passflow = undefined;
    vi.restoreAllMocks();
  });

  test('two calls that both get a 401 share one refresh and both succeed', async () => {
    localStorage.clear();
    const seeded = new StorageManager({ storage: localStorage, appId: TEST_CONFIG.appId });
    seeded.setDeliveryMode(TokenDeliveryMode.Cookie);
    seeded.setIdToken(idToken());
    seeded.setCsrfToken('csrf-1');
    vi.spyOn(AuthAPI.prototype, 'validateSession').mockResolvedValue({ id: 'user-1' });
    const refreshToken = vi
      .spyOn(AuthAPI.prototype, 'refreshToken')
      .mockResolvedValue({ id_token: idToken(), csrf_token: 'csrf-2', token_delivery: 'cookie' } as never);
    const instance = new Passflow({ ...TEST_CONFIG, refreshCoordination: 'none' });
    passflow = instance;

    const sent: InternalAxiosRequestConfig[] = [];
    const userClient = (instance as unknown as { userApi: { axiosClient: unknown } }).userApi.axiosClient as {
      instance: { defaults: { adapter: Adapter } };
    };
    // The access cookie is good once the refresh answered.
    userClient.instance.defaults.adapter = (config) => {
      sent.push(config);
      return refreshToken.mock.calls.length === 0 ? unauthorized(config) : Promise.resolve({ ...ok(config), data: [] });
    };

    await expect(Promise.all([instance.getUserPasskeys(), instance.getUserPasskeys()])).resolves.toEqual([[], []]);

    expect(refreshToken).toHaveBeenCalledTimes(1);
    expect(sent).toHaveLength(4);
    expect(sent.slice(2).map((config) => config.headers['X-CSRF-Token'])).toEqual(['csrf-2', 'csrf-2']);
    expect(instance.isAuthenticated()).toBe(true);
  });

  test('a cookie-mode sign-in on a page built in JSON mode: the next call carries credentials and the CSRF token', async () => {
    localStorage.clear();
    vi.spyOn(AuthAPI.prototype, 'validateSession').mockResolvedValue({ id: 'user-1' });
    vi.spyOn(AuthAPI.prototype, 'signIn').mockResolvedValue({
      id_token: idToken(),
      csrf_token: 'csrf-1',
      token_delivery: 'cookie',
    } as never);
    const instance = new Passflow({ ...TEST_CONFIG, refreshCoordination: 'none' });
    passflow = instance;
    const sent: InternalAxiosRequestConfig[] = [];
    const userClient = (instance as unknown as { userApi: { axiosClient: unknown } }).userApi.axiosClient as {
      instance: { defaults: { adapter: Adapter } };
    };
    userClient.instance.defaults.adapter = (config) => {
      sent.push(config);
      return Promise.resolve({ ...ok(config), data: [] });
    };

    await instance.signIn({ email: 'user@example.com', password: 'Password1!' });
    await instance.getUserPasskeys();

    expect(sent).toHaveLength(1);
    expect(sent[0]?.withCredentials).toBe(true);
    expect(sent[0]?.headers['X-CSRF-Token']).toBe('csrf-1');
    expect(sent[0]?.headers.Authorization).toBeUndefined();
  });
});
