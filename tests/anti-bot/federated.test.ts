/**
 * Federated start on human_only: a POST with the header, then the returned auth_url is followed.
 */
import { describe, expect, test } from 'vitest';
import {
  ANTI_BOT,
  CHALLENGE_PATH,
  decodeHeader,
  federatedPayload,
  HUMAN_BUILTIN,
  harness,
  header,
  until,
  VECTOR_A,
} from './harness';

const AUTH_URL = 'https://accounts.example/authorize?x=1';
const START = '/auth/federated/start/google';

describe('federated start on human_only', () => {
  test('REQ-1 redirect: POST with the header and JSON body, withCredentials, then navigates to auth_url', async () => {
    const h = harness(HUMAN_BUILTIN);
    h.sdk.federatedAuthWithRedirect(federatedPayload() as never);
    await until(() => h.navigations.length > 0);

    const [start] = h.wire(START);
    expect(start.method).toBe('POST');
    expect(decodeHeader(header(start, ANTI_BOT)!).number).toBe(42);
    expect(start.withCredentials).toBe(true);
    expect(start.data).toMatchObject({ redirect_url: federatedPayload().redirect_url, scopes: expect.any(Array) });
    expect(h.navigations).toEqual([AUTH_URL]);
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(1);
  });

  test('REQ-1 popup with an adapter without openPendingAuthUrl: openAuthUrl(auth_url) after the POST', async () => {
    const h = harness(HUMAN_BUILTIN);
    // Passflow.federatedAuthWithPopup returns void: wait for the window to open.
    h.sdk.federatedAuthWithPopup(federatedPayload() as never);
    await until(() => h.opened.length > 0);
    expect(h.wire(START)).toHaveLength(1);
    expect(header(h.wire(START)[0], ANTI_BOT)).toBeTruthy();
    expect(h.opened).toEqual([AUTH_URL]);
  });

  test('REQ-1 popup with openPendingAuthUrl: opened before the start answers, and given the auth_url', async () => {
    let release!: () => void;
    const held = new Promise<void>((r) => {
      release = r;
    });
    const urls: string[] = [];
    let openedAt = -1;
    const h = harness(HUMAN_BUILTIN, {
      platform: {
        openPendingAuthUrl: async (url: Promise<string>) => {
          openedAt = h.requests.length;
          urls.push(await url);
          return { callbackSearch: '', callbackHash: '' };
        },
      },
    });
    h.reply(CHALLENGE_PATH, async () => {
      await held;
      return VECTOR_A;
    });
    h.sdk.federatedAuthWithPopup(federatedPayload() as never);
    await until(() => openedAt >= 0);
    expect(h.wire(START)).toHaveLength(0);
    release();
    await until(() => urls.length > 0);
    expect(urls).toEqual([AUTH_URL]);
    expect(header(h.wire(START)[0], ANTI_BOT)).toBeTruthy();
    expect(h.opened).toEqual([]);
  });
});
