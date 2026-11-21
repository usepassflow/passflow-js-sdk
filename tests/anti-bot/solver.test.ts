/**
 * The built-in solver against the known vector: on the main thread (no worker URL) and in the
 * built worker file `dist/anti-bot-worker.js`, evaluated as a classic script in a fake worker scope.
 */
import { execFileSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import vm from 'node:vm';
import { beforeAll, describe, expect, test, vi } from 'vitest';
import { ANTI_BOT_SOLVE_FAILED_ERROR_ID } from '../../lib/index';
import {
  ANTI_BOT,
  CHALLENGE_PATH,
  decodeHeader,
  EMAIL,
  HUMAN_BUILTIN,
  harness,
  header,
  outcome,
  VECTOR_A,
  VECTOR_A_HEADER,
  VECTOR_B,
} from './harness';

const ROOT = resolve(__dirname, '../..');
const WORKER_FILE = resolve(ROOT, 'dist/anti-bot-worker.js');
const WORKER_URL = '/assets/anti-bot-worker.js';

const signIn = (h: ReturnType<typeof harness>) => h.sdk.signIn({ email: EMAIL, password: 'Password123!' } as never);

describe('main-thread solve (no worker URL)', () => {
  test('REQ-3 the vector challenge solves to 42 and the header is the exact base64 value', async () => {
    const h = harness(HUMAN_BUILTIN);
    await signIn(h);
    expect(header(h.wire('/auth/login')[0], ANTI_BOT)).toBe(VECTOR_A_HEADER);
  });

  test('REQ-3 the encoded JSON keys are in the order app, exp, max, salt, challenge, number, signature', async () => {
    const h = harness(HUMAN_BUILTIN);
    await signIn(h);
    const json = Buffer.from(header(h.wire('/auth/login')[0], ANTI_BOT)!, 'base64').toString('utf-8');
    expect(Object.keys(JSON.parse(json))).toEqual(['app', 'exp', 'max', 'salt', 'challenge', 'number', 'signature']);
    expect(json).toBe(
      JSON.stringify({
        app: VECTOR_A.app,
        exp: VECTOR_A.exp,
        max: VECTOR_A.max,
        salt: VECTOR_A.salt,
        challenge: VECTOR_A.challenge,
        number: 42,
        signature: VECTOR_A.signature,
      }),
    );
    expect(json).not.toContain('algorithm');
  });

  test('REQ-3 a second vector (another salt, small max) solves to 1234', async () => {
    const h = harness(HUMAN_BUILTIN);
    h.reply(CHALLENGE_PATH, VECTOR_B);
    await signIn(h);
    expect(decodeHeader(header(h.wire('/auth/login')[0], ANTI_BOT)!)).toEqual({
      app: VECTOR_B.app,
      exp: VECTOR_B.exp,
      max: VECTOR_B.max,
      salt: VECTOR_B.salt,
      challenge: VECTOR_B.challenge,
      number: 1234,
      signature: VECTOR_B.signature,
    });
  });

  test('REQ-3 a challenge with no answer in [0, max] fails with solve_failed and sends no sign-in', async () => {
    const h = harness(HUMAN_BUILTIN);
    // 42 is the answer, but max 10 excludes it.
    h.reply(CHALLENGE_PATH, { ...VECTOR_A, max: 10 });
    const error = await outcome(signIn(h));
    expect((error as { id?: string }).id).toBe(ANTI_BOT_SOLVE_FAILED_ERROR_ID);
    expect(h.wire('/auth/login')).toHaveLength(0);
  });
});

/** A Worker stand-in that evaluates the real built file as a classic script. */
function installWorker(source: string, mode: 'run' | 'error' = 'run') {
  const created: string[] = [];
  let terminated = 0;
  class FakeWorker {
    private listeners: Record<string, Array<(e: unknown) => void>> = {};
    onmessage: ((e: unknown) => void) | null = null;
    onerror: ((e: unknown) => void) | null = null;
    private scope: Record<string, unknown> & { onmessage?: (e: unknown) => void };
    private scopeListeners: Array<(e: unknown) => void> = [];

    constructor(url: string | URL) {
      created.push(String(url));
      const toMain = (data: unknown) => setTimeout(() => this.dispatch('message', { data: structuredClone(data) }), 0);
      this.scope = {
        crypto: webcrypto,
        TextEncoder,
        postMessage: toMain,
        addEventListener: (type: string, fn: (e: unknown) => void) => {
          if (type === 'message') this.scopeListeners.push(fn);
        },
        removeEventListener: () => {},
        console,
      };
      this.scope.self = this.scope;
      this.scope.globalThis = this.scope;
      if (mode === 'run') {
        vm.runInNewContext(source, this.scope, { filename: 'anti-bot-worker.js' });
      } else {
        setTimeout(() => this.dispatch('error', { message: 'failed to load', type: 'error' }), 0);
      }
    }
    private dispatch(type: string, event: unknown) {
      if (type === 'message') this.onmessage?.(event);
      if (type === 'error') this.onerror?.(event);
      for (const fn of this.listeners[type] ?? []) fn(event);
    }
    addEventListener(type: string, fn: (e: unknown) => void) {
      this.listeners[type] = [...(this.listeners[type] ?? []), fn];
    }
    removeEventListener(type: string, fn: (e: unknown) => void) {
      this.listeners[type] = (this.listeners[type] ?? []).filter((f) => f !== fn);
    }
    postMessage(data: unknown) {
      const event = { data: structuredClone(data) };
      setTimeout(() => {
        this.scope.onmessage?.(event);
        for (const fn of this.scopeListeners) fn(event);
      }, 0);
    }
    terminate() {
      terminated += 1;
    }
  }
  vi.stubGlobal('Worker', FakeWorker);
  return { created, terminated: () => terminated };
}

describe('the built worker file', () => {
  let source = '';
  beforeAll(() => {
    execFileSync('pnpm', ['build:worker'], { cwd: ROOT, stdio: 'pipe' });
    expect(existsSync(WORKER_FILE)).toBe(true);
    source = readFileSync(WORKER_FILE, 'utf-8');
  }, 60_000);

  test('REQ-3 is a classic script (no ES module syntax), so it loads as a same-origin worker', () => {
    expect(() => new vm.Script(source)).not.toThrow();
  });

  test('REQ-3 solves the vector in the worker; the header is the exact base64 value', async () => {
    const worker = installWorker(source);
    const h = harness(HUMAN_BUILTIN, { config: { antiBotWorkerUrl: WORKER_URL } });
    await signIn(h);
    expect(worker.created).toEqual([WORKER_URL]);
    expect(worker.created[0]).not.toMatch(/^(blob|data):/);
    expect(header(h.wire('/auth/login')[0], ANTI_BOT)).toBe(VECTOR_A_HEADER);
    expect(worker.terminated()).toBeGreaterThanOrEqual(1);
  });

  test('REQ-3 solves the second vector in the worker to 1234', async () => {
    installWorker(source);
    const h = harness(HUMAN_BUILTIN, { config: { antiBotWorkerUrl: WORKER_URL } });
    h.reply(CHALLENGE_PATH, VECTOR_B);
    await signIn(h);
    expect(decodeHeader(header(h.wire('/auth/login')[0], ANTI_BOT)!).number).toBe(1234);
  });

  test('REQ-3 a worker that fails to load fails with solve_failed and sends no sign-in', async () => {
    installWorker(source, 'error');
    const h = harness(HUMAN_BUILTIN, { config: { antiBotWorkerUrl: WORKER_URL } });
    const error = await outcome(signIn(h));
    expect((error as { id?: string }).id).toBe(ANTI_BOT_SOLVE_FAILED_ERROR_ID);
    expect(h.wire('/auth/login')).toHaveLength(0);
  });

  test('REQ-3 with a worker URL but no Worker global, it solves on the main thread', async () => {
    vi.stubGlobal('Worker', undefined);
    const h = harness(HUMAN_BUILTIN, { config: { antiBotWorkerUrl: WORKER_URL } });
    await signIn(h);
    expect(header(h.wire('/auth/login')[0], ANTI_BOT)).toBe(VECTOR_A_HEADER);
  });
});
