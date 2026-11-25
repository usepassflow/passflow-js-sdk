/**
 * A POST federated start follows the returned auth_url only when it is an http or https address.
 */
import { describe, expect, test } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import { federatedPayload, HUMAN_BUILTIN, harness, until } from './harness';

const START = '/auth/federated/start/google';
const REFUSED = [
  'javascript:alert(1)',
  ' JavaScript:alert(1)',
  'data:text/html,<p>x</p>',
  'vbscript:x',
  'not a url',
  '',
  'https://',
  'httpx://a',
  'https-evil:x',
];

describe('federated start address', () => {
  test.each(REFUSED)('redirect refuses %j: no navigation, one federated.redirect error', async (address) => {
    const h = harness(HUMAN_BUILTIN);
    h.reply(START, { auth_url: address });
    h.sdk.federatedAuthWithRedirect(federatedPayload() as never);
    await until(() => h.of(PassflowEvent.Error).length > 0 || h.navigations.length > 0);
    expect(h.navigations).toEqual([]);
    expect(h.of(PassflowEvent.Error)).toEqual([expect.objectContaining({ operation: 'federated.redirect' })]);
  });

  test.each(REFUSED)('popup refuses %j: no window, one federated.popup error', async (address) => {
    const h = harness(HUMAN_BUILTIN);
    h.reply(START, { auth_url: address });
    h.sdk.federatedAuthWithPopup(federatedPayload() as never);
    await until(() => h.of(PassflowEvent.Error).length > 0 || h.opened.length > 0);
    expect(h.opened).toEqual([]);
    expect(h.of(PassflowEvent.Error)).toEqual([expect.objectContaining({ operation: 'federated.popup' })]);
  });

  test('popup with openPendingAuthUrl: the pending window gets a rejection, never the address', async () => {
    const given: string[] = [];
    let rejected: unknown;
    const h = harness(HUMAN_BUILTIN, {
      platform: {
        openPendingAuthUrl: async (url: Promise<string>) => {
          try {
            given.push(await url);
          } catch (error) {
            rejected = error;
            throw error;
          }
          return { callbackSearch: '', callbackHash: '' };
        },
      },
    });
    h.reply(START, { auth_url: 'javascript:alert(1)' });
    h.sdk.federatedAuthWithPopup(federatedPayload() as never);
    await until(() => given.length > 0 || rejected !== undefined);
    expect(given).toEqual([]);
    expect(rejected).toBeInstanceOf(Error);
  });

  test.each(['https://accounts.example/authorize?x=1', 'http://localhost:8080/authorize', 'HTTPS://A.example/x'])(
    'redirect follows %s',
    async (address) => {
      const h = harness(HUMAN_BUILTIN);
      h.reply(START, { auth_url: address });
      h.sdk.federatedAuthWithRedirect(federatedPayload() as never);
      await until(() => h.navigations.length > 0);
      expect(h.navigations).toEqual([address]);
    },
  );
});
