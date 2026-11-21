/**
 * A real `Passflow` over a stubbed axios transport. Every request (including `GET /app/settings`
 * and the challenge) goes through one recorder, so tests read the wire and nothing else.
 */
import { webcrypto } from 'node:crypto';
import { URLSearchParams as NativeURLSearchParams } from 'node:url';
import axios, { type AxiosAdapter, AxiosError, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, expect, vi } from 'vitest';
import { Passflow, type PassflowConfig, PassflowEvent } from '../../lib/index';
import { TEST_CONFIG, VALID_TOKENS } from '../helpers/fixtures';
import { createMockPlatform } from '../helpers/mock-platform';

export const ANTI_BOT = 'X-Passflow-Anti-Bot';
export const AGENT_TOOL = 'X-Passflow-Agent-Tool';
export const CHALLENGE_PATH = '/auth/anti-bot/challenge';
export const DEVICE_CHALLENGE_PATH = '/oidc/device/anti-bot/challenge';
export const SETTINGS_PATH = '/app/settings';
export const EMAIL = 'qa@example.com';

/** The vector: salt "0" x 32, number 42. */
export const VECTOR_A = {
  algorithm: 'SHA-256',
  app: 'app_test',
  exp: 1795000000,
  max: 50000,
  salt: '00000000000000000000000000000000',
  challenge: '65d9a4f8fe9abc50f929521ab3346fc213f21e2503507a0d77ad7e2ae195c56f',
  signature: 'ab'.repeat(32),
};
/** A second challenge with another salt: number 1234. */
export const VECTOR_B = {
  algorithm: 'SHA-256',
  app: 'app_test',
  exp: 1795000000,
  max: 2000,
  salt: '00112233445566778899aabbccddeeff',
  challenge: '8ea092a8015b7f4e96d99819caed8bb5ddcd0f636cf2d11aff9a5a3c51cc2ff8',
  signature: 'cd'.repeat(32),
};
/** Exact base64 header value for VECTOR_A solved with 42. */
export const VECTOR_A_HEADER =
  'eyJhcHAiOiJhcHBfdGVzdCIsImV4cCI6MTc5NTAwMDAwMCwibWF4Ijo1MDAwMCwic2FsdCI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwiY2hhbGxlbmdlIjoiNjVkOWE0ZjhmZTlhYmM1MGY5Mjk1MjFhYjMzNDZmYzIxM2YyMWUyNTAzNTA3YTBkNzdhZDdlMmFlMTk1YzU2ZiIsIm51bWJlciI6NDIsInNpZ25hdHVyZSI6ImFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifQ==';

export const HUMAN_BUILTIN = { pkce_enabled: false, bot_mode: 'human_only', anti_bot: { provider: 'builtin' } };
export const HUMAN_NO_ANTI_BOT = { pkce_enabled: false, bot_mode: 'human_only' };
export const HUMAN_BYO = { pkce_enabled: false, bot_mode: 'human_only', anti_bot: { provider: 'turnstile', site_key: 'k' } };
export const BOT_FRIENDLY = { pkce_enabled: false, bot_mode: 'bot_friendly' };
export const NO_BOT_MODE = { pkce_enabled: false };

export type Fault = { fault: true; status: number; data?: unknown; headers?: Record<string, string> };
export const fault = (status: number, data?: unknown, headers?: Record<string, string>): Fault => ({
  fault: true,
  status,
  data,
  headers,
});
export const apiError = (id: string, status: number) =>
  fault(status, { error: { id, message: id, status, location: '/auth', time: '2026-11-21T00:00:00Z' } });

type Reply = unknown | ((request: Recorded) => unknown);
export type Recorded = {
  method: string;
  path: string;
  headers: Record<string, string>;
  data: unknown;
  withCredentials: boolean | undefined;
};

export const decodeHeader = (value: string) => JSON.parse(Buffer.from(value, 'base64').toString('utf-8'));

const clients: Passflow[] = [];
const originalAdapter = axios.defaults.adapter;

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  vi.stubGlobal('URLSearchParams', NativeURLSearchParams);
  vi.stubGlobal('crypto', webcrypto);
});
afterEach(() => {
  for (const sdk of clients.splice(0)) sdk.dispose();
  axios.defaults.adapter = originalAdapter;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const headerMap = (request: InternalAxiosRequestConfig): Record<string, string> => {
  const raw = request.headers as unknown as { toJSON?: () => Record<string, unknown> } & Record<string, unknown>;
  const flat = typeof raw?.toJSON === 'function' ? raw.toJSON() : { ...(raw ?? {}) };
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(flat)) if (v !== undefined && v !== null && v !== false) out[k.toLowerCase()] = String(v);
  return out;
};

export function harness(settings: Reply, options: { config?: Partial<PassflowConfig>; platform?: object } = {}) {
  const requests: Recorded[] = [];
  const timeline: string[] = [];
  const replies = new Map<string, Reply>();
  const queues = new Map<string, Reply[]>();
  const navigations: string[] = [];
  const opened: string[] = [];

  replies.set(SETTINGS_PATH, settings);
  replies.set(CHALLENGE_PATH, VECTOR_A);
  replies.set(DEVICE_CHALLENGE_PATH, VECTOR_A);
  replies.set('/auth/login', { ...VALID_TOKENS });
  replies.set('/auth/register', { ...VALID_TOKENS });
  replies.set('/auth/passwordless/start', { challenge_id: 'pl-1', expires_at: new Date(Date.now() + 60_000).toISOString() });
  replies.set('/auth/passwordless/complete', { ...VALID_TOKENS });
  replies.set('/auth/password/reset', { result: 'ok' });
  replies.set('/auth/passkey/register/start', {
    challenge_id: 'pk-reg',
    publicKey: { user: { id: 'uid', name: 'u', displayName: 'u' }, challenge: 'ch', rp: { id: 'rp', name: 'rp' } },
  });
  replies.set('/auth/passkey/register/complete', { ...VALID_TOKENS });
  replies.set('/auth/passkey/authenticate/start', { challenge_id: 'pk-auth', publicKey: { challenge: 'ch', rpId: 'rp' } });
  replies.set('/auth/passkey/authenticate/complete', { ...VALID_TOKENS });
  replies.set('/auth/federated/start/google', { auth_url: 'https://accounts.example/authorize?x=1' });
  replies.set('/auth/pkce_exchange', { ...VALID_TOKENS });
  replies.set('/auth/refresh', { ...VALID_TOKENS });
  replies.set('/auth/validate', { ...VALID_TOKENS });
  replies.set('/user/me', { id: 'user-123' });
  replies.set('/user/logout', { status: 'ok' });

  const adapter: AxiosAdapter = async (request) => {
    const path = new URL(request.url ?? '', 'https://api.example').pathname;
    const data = typeof request.data === 'string' ? safeJson(request.data) : request.data;
    const recorded: Recorded = {
      method: (request.method ?? 'get').toUpperCase(),
      path,
      headers: headerMap(request),
      data,
      withCredentials: request.withCredentials,
    };
    requests.push(recorded);
    timeline.push(`request:${path}`);
    const queue = queues.get(path);
    let answer = queue?.length ? queue.shift() : replies.get(path);
    if (typeof answer === 'function') answer = await (answer as (r: Recorded) => unknown)(recorded);
    if (answer && typeof answer === 'object' && 'fault' in answer) {
      const f = answer as Fault;
      const response = {
        status: f.status,
        statusText: 'Failure',
        data: f.data ?? {},
        headers: f.headers ?? {},
        config: request,
      };
      throw new AxiosError('Request failed', 'ERR_BAD_REQUEST', request, {}, response);
    }
    if (answer === undefined) throw new Error(`Unexpected HTTP request: ${recorded.method} ${path}`);
    return { data: answer, status: 200, statusText: 'OK', headers: {}, config: request };
  };
  axios.defaults.adapter = adapter;

  const platform = createMockPlatform({
    storage: {
      getItem: (key: string) => localStorage.getItem(key),
      setItem: (key: string, value: string) => localStorage.setItem(key, value),
      removeItem: (key: string) => localStorage.removeItem(key),
    },
    navigateTo: vi.fn((url: string) => {
      navigations.push(url);
    }),
    openAuthUrl: vi.fn(async (url: string) => {
      opened.push(url);
      return { callbackSearch: '', callbackHash: '' };
    }),
    passkeys: {
      startRegistration: vi.fn().mockResolvedValue({ id: 'reg-id', rawId: 'reg-id', type: 'public-key', response: {} }),
      startAuthentication: vi.fn().mockResolvedValue({ id: 'auth-id', rawId: 'auth-id', type: 'public-key', response: {} }),
    },
    ...(options.platform ?? {}),
  });

  const sdk = new Passflow({
    ...TEST_CONFIG,
    parseQueryParams: false,
    refreshCoordination: 'none',
    platform,
    ...options.config,
  } as PassflowConfig);
  clients.push(sdk);

  const events: Array<{ event: PassflowEvent; payload: unknown }> = [];
  sdk.subscribe({
    onAuthChange: (event, payload) => {
      events.push({ event, payload });
      timeline.push(`event:${event}`);
    },
  });

  return {
    sdk,
    platform,
    requests,
    timeline,
    events,
    navigations,
    opened,
    reply: (path: string, reply: Reply) => replies.set(path, reply),
    queue: (path: string, ...answers: Reply[]) => queues.set(path, answers),
    wire: (path: string) => requests.filter((r) => r.path === path),
    challenges: () => requests.filter((r) => r.path === CHALLENGE_PATH || r.path === DEVICE_CHALLENGE_PATH),
    withAntiBot: () => requests.filter((r) => r.headers[ANTI_BOT.toLowerCase()] !== undefined),
    of: (event: PassflowEvent) => events.filter((e) => e.event === event).map((e) => e.payload),
    antiBotEvents: () =>
      events.filter((e) => e.event === PassflowEvent.AntiBotSolving || e.event === PassflowEvent.AntiBotSolved),
    clear: () => {
      requests.length = 0;
      timeline.length = 0;
      events.length = 0;
    },
  };
}
export type Harness = ReturnType<typeof harness>;

const safeJson = (s: string) => {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
};

export const header = (r: Recorded | undefined, name: string) => r?.headers[name.toLowerCase()];

/** Waits until `check` passes (real timers), for void-returning calls such as federated redirect. */
export async function until(check: () => boolean, ms = 4000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  expect(check(), 'observable result did not settle').toBe(true);
}

export const outcome = (p: Promise<unknown>) =>
  p.then(
    () => {
      throw new Error('call must reject, not resolve');
    },
    (e: unknown) => e,
  );

export const passwordlessPayload = () => ({
  email: EMAIL,
  challenge_type: 'otp' as const,
  redirect_url: 'https://app.example/callback',
  scopes: ['id', 'offline'],
});
export const federatedPayload = () => ({
  provider: 'google' as import('../../lib/api').Providers,
  redirect_url: 'https://app.example/callback',
});

/** The covered calls, each with its route and expected challenge identifier. */
export const COVERED: Array<{
  name: string;
  route: string;
  identifier: string | undefined;
  run: (h: Harness, options?: { agentTool?: boolean }) => Promise<unknown>;
}> = [
  {
    name: 'signIn',
    route: '/auth/login',
    identifier: EMAIL,
    run: (h, o) => h.sdk.signIn({ email: EMAIL, password: 'Password123!' } as never, o),
  },
  {
    name: 'signUp',
    route: '/auth/register',
    identifier: EMAIL,
    run: (h, o) => h.sdk.signUp({ user: { email: EMAIL, password: 'Password123!' } } as never, o),
  },
  {
    name: 'passwordlessSignIn',
    route: '/auth/passwordless/start',
    identifier: EMAIL,
    run: (h, o) => h.sdk.passwordlessSignIn(passwordlessPayload() as never, o),
  },
  {
    name: 'passkeyRegister',
    route: '/auth/passkey/register/start',
    identifier: 'passkey-user',
    run: (h, o) =>
      h.sdk.passkeyRegister(
        {
          passkey_username: 'passkey-user',
          relying_party_id: 'rp',
          redirect_url: 'https://app.example',
          scopes: ['id'],
        } as never,
        o,
      ),
  },
  {
    name: 'passkeyAuthenticate',
    route: '/auth/passkey/authenticate/start',
    identifier: undefined,
    run: (h, o) => h.sdk.passkeyAuthenticate({ relying_party_id: 'rp' } as never, o),
  },
  {
    name: 'sendPasswordResetEmail',
    route: '/auth/password/reset',
    identifier: EMAIL,
    run: (h, o) => h.sdk.sendPasswordResetEmail({ email: EMAIL, redirect_url: 'https://app.example' } as never, o),
  },
  {
    name: 'federatedAuthWithRedirect',
    route: '/auth/federated/start/google',
    identifier: undefined,
    run: async (h, o) => {
      h.sdk.federatedAuthWithRedirect(federatedPayload() as never, o);
      await until(() => h.navigations.length > 0);
    },
  },
];

/** Runs a call and ignores its outcome; the wire is what is asserted. */
export const attempt = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch {
    /* outcome asserted elsewhere */
  }
};
