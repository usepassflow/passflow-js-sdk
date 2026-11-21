/**
 * Nothing changes for a bot_friendly app, for settings without bot_mode, for a failed settings
 * read, and with no app id: no challenge, no header, no anti-bot event, the same request body.
 */
import { describe, expect, test } from 'vitest';
import {
  AGENT_TOOL,
  ANTI_BOT,
  attempt,
  BOT_FRIENDLY,
  CHALLENGE_PATH,
  COVERED,
  DEVICE_CHALLENGE_PATH,
  fault,
  federatedPayload,
  type Harness,
  HUMAN_BUILTIN,
  harness,
  header,
  NO_BOT_MODE,
  until,
} from './harness';

const MODES: Array<{ name: string; settings: unknown; config?: Record<string, unknown> }> = [
  { name: 'bot_friendly', settings: BOT_FRIENDLY },
  { name: 'settings without bot_mode', settings: NO_BOT_MODE },
  { name: 'a failed settings read (500)', settings: fault(500, { message: 'boom' }) },
];

const expectUntouched = (h: Harness) => {
  expect(h.wire(CHALLENGE_PATH)).toHaveLength(0);
  expect(h.wire(DEVICE_CHALLENGE_PATH)).toHaveLength(0);
  for (const r of h.requests) {
    expect(header(r, ANTI_BOT), `${r.method} ${r.path}`).toBeUndefined();
    expect(header(r, AGENT_TOOL), `${r.method} ${r.path}`).toBeUndefined();
  }
  expect(h.antiBotEvents()).toEqual([]);
};

/** Federated redirect is void; on a failed settings read it may not navigate, so wait a moment either way. */
const runSettled = async (h: Harness, c: (typeof COVERED)[number]) => {
  if (c.name === 'federatedAuthWithRedirect') {
    h.sdk.federatedAuthWithRedirect(federatedPayload() as never);
    await new Promise((r) => setTimeout(r, 100));
    return;
  }
  await attempt(c.run(h));
};

const normalise = (data: unknown) => {
  if (!data || typeof data !== 'object') return data;
  const { device: _device, ...rest } = data as Record<string, unknown>;
  return rest;
};

describe.each(MODES)('$name', ({ settings }) => {
  test.each(COVERED)('REQ-6 $name: no challenge, no header, no anti-bot event', async (c) => {
    const h = harness(settings);
    await runSettled(h, c);
    expectUntouched(h);
  });
});

describe('no app id', () => {
  test.each(COVERED.filter((c) => c.name !== 'federatedAuthWithRedirect'))(
    'REQ-6 $name: no challenge, no header',
    async (c) => {
      const h = harness(HUMAN_BUILTIN, { config: { appId: undefined } });
      await runSettled(h, c);
      expectUntouched(h);
    },
  );
});

describe('the covered request on bot_friendly is the human_only request without the header', () => {
  test.each(COVERED.filter((c) => c.name !== 'federatedAuthWithRedirect'))(
    'REQ-6 $name: same method, path, body and header names',
    async (c) => {
      const friendly = harness(BOT_FRIENDLY);
      await c.run(friendly);
      const human = harness(HUMAN_BUILTIN);
      await c.run(human);

      const a = friendly.wire(c.route)[0];
      const b = human.wire(c.route)[0];
      expect(a.method).toBe(b.method);
      expect(normalise(a.data)).toEqual(normalise(b.data));
      const names = (r: typeof a) => Object.keys(r.headers).sort();
      expect(names(a)).toEqual(names(b).filter((n) => n !== ANTI_BOT.toLowerCase()));
    },
  );
});

describe('federated on bot_friendly', () => {
  test('REQ-6 redirect navigates to the GET start URL with no POST', async () => {
    const h = harness(BOT_FRIENDLY);
    h.sdk.federatedAuthWithRedirect(federatedPayload() as never);
    await until(() => h.navigations.length > 0);
    expect(h.wire('/auth/federated/start/google')).toHaveLength(0);
    const url = new URL(h.navigations[0]);
    expect(url.pathname).toContain('/auth/federated/start/google');
    expect(url.searchParams.toString()).not.toMatch(/anti/i);
    expectUntouched(h);
  });

  test('REQ-6 popup opens pending and follows the GET start URL; no POST', async () => {
    const urls: string[] = [];
    const h = harness(BOT_FRIENDLY, {
      platform: {
        openPendingAuthUrl: async (url: Promise<string>) => {
          urls.push(await url);
          return { callbackSearch: '', callbackHash: '' };
        },
      },
    });
    // Passflow.federatedAuthWithPopup returns void: wait for the window to get its URL.
    h.sdk.federatedAuthWithPopup(federatedPayload() as never);
    await until(() => urls.length > 0);
    expect(h.opened).toHaveLength(0);
    expect(new URL(urls[0]).pathname).toContain('/auth/federated/start/google');
    expect(new URL(urls[0]).searchParams.toString()).not.toMatch(/anti/i);
    expect(h.wire('/auth/federated/start/google')).toHaveLength(0);
    expectUntouched(h);
  });
});
