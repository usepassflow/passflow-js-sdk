/**
 * A JSON session with an access token and no refresh token, on real `Passflow` instances as tabs
 * (tests/refresh/sdk-tabs.ts). Such a session lives as long as its access token is stored: it ends
 * when storage is emptied or another user signs in, not because no refresh token is stored.
 */
import { afterEach, describe, expect, test, vi } from 'vitest';
import { AuthAPI } from '../../lib/api';
import { PassflowEvent } from '../../lib/store';
import type { Tokens } from '../../lib/types';
import { accessOnlyOf, createSdkWorld, endsOf, openTab, outage, pairOf, type SdkWorld, type Tab } from './sdk-tabs';

type ForegroundTab = ReturnType<typeof openTab>;

let world: SdkWorld | undefined;

afterEach(() => {
  world?.dispose();
  world = undefined;
  vi.restoreAllMocks();
});

/** Opens two tabs over a stored session, or over an empty storage. */
async function setup(
  stored: Tokens | undefined,
  answer?: Parameters<typeof createSdkWorld>[0],
): Promise<{ w: SdkWorld; a: ForegroundTab; b: ForegroundTab }> {
  const w = createSdkWorld(answer);
  world = w;
  vi.spyOn(AuthAPI.prototype, 'logOut').mockResolvedValue({ status: 'ok' } as never);
  if (stored) w.seed(stored);
  const a = openTab(w, 'a');
  const b = openTab(w, 'b');
  await w.ready();
  return { w, a, b };
}

const tokenKeys = (w: SdkWorld): string[] => [...w.shared.items.keys()].filter((key) => key !== 'passflowDeviceId');
/** Another tab empties the storage, with storage events. */
const emptyStorage = (w: SdkWorld): void => {
  for (const key of tokenKeys(w)) w.shared.view('other').removeItem(key);
};
/** The storage was emptied and this page never got the storage events. */
const emptyStorageUnseen = (w: SdkWorld): void => {
  for (const key of tokenKeys(w)) w.shared.items.delete(key);
};

/** Another tab takes the refresh lock; the answer lets it go. */
async function holdLock(w: SdkWorld): Promise<() => Promise<unknown>> {
  let release = (): void => {};
  const held = w.locks.forTab('other').request(
    'passflow-refresh',
    {},
    () =>
      new Promise<void>((resolve) => {
        release = resolve;
      }),
  );
  await w.run(1);
  return () => {
    release();
    return held;
  };
}

const noEnds = (tab: Tab): void => expect(endsOf(tab).map((e) => e.event)).toEqual([]);
const signOutOrigins = (tab: Tab): unknown[] => tab.of<{ origin?: string }>(PassflowEvent.SignOut).map((p) => p.origin);
const endedElsewhere = (tab: Tab): void => {
  expect(endsOf(tab).map((e) => e.event)).toEqual([PassflowEvent.SignOut]);
  expect(signOutOrigins(tab)).toEqual(['other-tab']);
  expect(tab.passflow.isAuthenticated()).toBe(false);
};
const keeps = (tab: Tab, tokens: Tokens): void => {
  noEnds(tab);
  expect(tab.passflow.isAuthenticated()).toBe(true);
  expect(tab.passflow.getCachedTokens()?.access_token === tokens.access_token).toBe(true);
};

describe('an access-only session stays while its access token is stored', () => {
  test('a stored session survives the foreground', async () => {
    const tokens = accessOnlyOf();
    const { w, a } = await setup(tokens);

    a.foreground();
    await w.run(3_000);

    keeps(a, tokens);
  });

  test('a session set with setTokens survives the foreground', async () => {
    const tokens = accessOnlyOf();
    const { w, a } = await setup(undefined);
    a.passflow.setTokens(tokens);
    await w.ready();

    a.foreground();
    await w.run(3_000);

    keeps(a, tokens);
  });

  test('another tab signing the same user in access-only leaves this tab signed in', async () => {
    const tokens = accessOnlyOf();
    const { w, a, b } = await setup(tokens);

    b.passflow.setTokens(accessOnlyOf());
    await w.run(3_000);

    keeps(a, tokens);
  });

  test('a rejected refreshToken() leaves the session in place at the next foreground', async () => {
    const tokens = accessOnlyOf();
    const { w, a } = await setup(tokens);
    const call = w.track(a.passflow.refreshToken());
    await w.run(1);
    expect(call.status).toBe('rejected');
    expect((call.error as Error).message).toBe('No refresh token found');

    a.foreground();
    await w.run(3_000);

    keeps(a, tokens);
    expect(w.requests.length).toBe(0);
  });

  test('a tab whose session ended and that signs in access-only survives the foreground', async () => {
    const tokens = accessOnlyOf();
    const { w, a } = await setup(pairOf('user-1', { fresh: true }));
    emptyStorage(w);
    await w.run(3_000);
    endedElsewhere(a);
    a.events.length = 0;

    a.passflow.setTokens(tokens);
    await w.run();
    a.foreground();
    await w.run(3_000);

    keeps(a, tokens);
  });

  test('a refresh token that is gone again at the lock grant leaves the session in place', async () => {
    const { w, a } = await setup(accessOnlyOf('user-1', false));
    let release = (): void => {};
    const held = w.locks.forTab('other').request(
      'passflow-refresh',
      {},
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    await w.run(1);
    w.shared.items.set('refresh', pairOf().refresh_token ?? '');
    const call = w.track(a.passflow.getTokensWithRefresh());
    await w.run(1);
    expect(call.status).toBe('pending');

    w.shared.items.delete('refresh');
    release();
    await held;
    await w.run(3_000);

    noEnds(a);
    expect(w.requests.length).toBe(0);
  });
});

describe('an access-only session ends when it really ended elsewhere', () => {
  test('storage emptied by another tab signs this tab out', async () => {
    const { w, a } = await setup(accessOnlyOf());
    emptyStorage(w);
    await w.run(1);
    endedElsewhere(a);
  });

  test('storage emptied while this tab was frozen is found at the foreground', async () => {
    const { w, a } = await setup(accessOnlyOf());
    w.clock.freeze('a');
    emptyStorageUnseen(w);
    await w.run(3_000);
    w.clock.thaw('a');
    noEnds(a);

    a.foreground();
    await w.run(3_000);

    endedElsewhere(a);
  });

  test("another tab's logOut() signs this tab out", async () => {
    const { w, a, b } = await setup(accessOnlyOf());
    const call = w.track(b.passflow.logOut());
    await w.run(6_000);
    expect(call.status).toBe('resolved');
    endedElsewhere(a);
  });

  test("another tab's reset() signs this tab out", async () => {
    const { w, a, b } = await setup(accessOnlyOf());
    b.passflow.reset();
    await w.run(3_000);
    endedElsewhere(a);
  });

  test("another user's access-only sign-in expires this tab's session", async () => {
    const { w, a, b } = await setup(accessOnlyOf('user-1'));
    b.passflow.setTokens(accessOnlyOf('user-2'));
    await w.run(3_000);
    expect(endsOf(a).map((e) => e.event)).toEqual([PassflowEvent.SessionExpired]);
    expect(a.of(PassflowEvent.SessionExpired)).toMatchObject([{ reason: 'identity_changed' }]);
  });
});

describe('sessions with a refresh token', () => {
  test("an access-only tab adopts another tab's full pair", async () => {
    const pair = pairOf('user-1', { fresh: true });
    const { w, a, b } = await setup(accessOnlyOf());

    b.passflow.setTokens(pair);
    await w.run(3_000);

    noEnds(a);
    expect(a.of<{ source?: string }>(PassflowEvent.Refresh).map((p) => p.source)).toEqual(['adopted']);
    expect(a.passflow.getCachedTokens()?.refresh_token === pair.refresh_token).toBe(true);
  });

  test('a full-pair tab whose stored refresh key alone is removed signs out after 2000 ms', async () => {
    const { w, a } = await setup(pairOf('user-1', { fresh: true }));
    w.shared.view('other').removeItem('refresh');
    await w.run(1_999);
    noEnds(a);
    await w.run(1);
    endedElsewhere(a);
  });

  test('a full-pair tab that signs in access-only while it waits on an emptied storage stays signed in', async () => {
    const tokens = accessOnlyOf();
    const { w, a } = await setup(pairOf('user-1', { fresh: true }));
    emptyStorage(w);
    await w.run(500);
    noEnds(a);

    a.passflow.setTokens(tokens);
    await w.run(3_000);

    keeps(a, tokens);
  });

  test('a full-pair tab whose storage is emptied signs out after 2000 ms', async () => {
    const { w, a } = await setup(pairOf('user-1', { fresh: true }));
    emptyStorage(w);
    await w.run(1_999);
    noEnds(a);
    await w.run(1);
    endedElsewhere(a);
  });
});

describe('an expired access token', () => {
  test('with no refresh token, session({ doRefresh: true }) reports an expired session', async () => {
    const { w, a } = await setup(accessOnlyOf('user-1', false));
    const createSession = vi.fn(async () => {});
    const expiredSession = vi.fn(async () => {});

    await a.passflow.session({ createSession, expiredSession, doRefresh: true });

    expect(createSession.mock.calls.length).toBe(0);
    expect(expiredSession).toHaveBeenCalledTimes(1);
    expect(w.requests.length).toBe(0);
  });

  test('with no refresh token, getTokens(true) resolves undefined', async () => {
    const { w, a } = await setup(accessOnlyOf('user-1', false));
    const tokens = await a.passflow.getTokens(true);
    expect(tokens === undefined).toBe(true);
    expect(a.of<{ message?: string }>(PassflowEvent.Error).map((p) => p.message)).toEqual(['No refresh token found']);
    expect(w.requests.length).toBe(0);
  });

  test('whose refresh token is gone again at the lock grant, getTokens(true) resolves undefined', async () => {
    const { w, a } = await setup(accessOnlyOf('user-1', false));
    const unlock = await holdLock(w);
    w.shared.items.set('refresh', pairOf().refresh_token ?? '');
    const call = w.track(a.passflow.getTokens(true));
    await w.run(1);
    expect(call.status).toBe('pending');

    w.shared.items.delete('refresh');
    await unlock();
    await w.run(1);

    expect(call.status).toBe('resolved');
    expect(call.value === undefined).toBe(true);
    expect(w.requests.length).toBe(0);
    noEnds(a);
  });

  test("getTokens(true) waiting for the lock resolves the pair it adopts from another tab's sign-in", async () => {
    const pair = pairOf('user-1', { fresh: true });
    const { w, a, b } = await setup(accessOnlyOf('user-1', false));
    const unlock = await holdLock(w);
    w.shared.items.set('refresh', pairOf().refresh_token ?? '');
    const call = w.track(a.passflow.getTokens(true));
    await w.run(1);
    expect(call.status).toBe('pending');

    b.passflow.setTokens(pair);
    await unlock();
    await w.run(1);

    expect(call.status).toBe('resolved');
    expect(call.value?.access_token === pair.access_token).toBe(true);
    expect(call.value?.refresh_token === pair.refresh_token).toBe(true);
    expect(w.requests.length).toBe(0);
    noEnds(a);
  });

  test('stored over a full pair by another tab, session({ doRefresh: true }) keeps the pair until the wait ends', async () => {
    const pair = pairOf('user-1', { fresh: true });
    const { w, a, b } = await setup(pair);
    const createSession = vi.fn(async (_session: { tokens?: Tokens }) => {});
    const expiredSession = vi.fn(async () => {});
    b.passflow.setTokens(accessOnlyOf('user-1', false));
    await w.run(500);

    const call = w.track(a.passflow.session({ createSession, expiredSession, doRefresh: true }));
    await w.run(1);

    expect(call.status).toBe('resolved');
    expect(createSession).toHaveBeenCalledTimes(1);
    expect(createSession.mock.calls[0]?.[0].tokens?.access_token === pair.access_token).toBe(true);
    expect(expiredSession.mock.calls.length).toBe(0);
    expect(w.requests.length).toBe(0);
    noEnds(a);
    await w.run(1_498);
    noEnds(a);
    await w.run(1);
    expect(signOutOrigins(a)).toEqual(['other-tab']);
  });

  test('with no refresh token, getTokensWithRefresh() still resolves the cached tokens', async () => {
    const stored = accessOnlyOf('user-1', false);
    const { a } = await setup(stored);
    const tokens = await a.passflow.getTokensWithRefresh();
    expect(tokens?.access_token === stored.access_token).toBe(true);
  });

  test('of a full pair, getTokens(true) resolves the kept tokens after a transient refresh failure', async () => {
    const stored = pairOf();
    const { w, a } = await setup(stored, () => ({ error: outage() }));
    const call = w.track(a.passflow.getTokens(true));
    await w.run(1);
    expect(call.status).toBe('resolved');
    expect(call.value?.access_token === stored.access_token).toBe(true);
    expect(call.value?.refresh_token === stored.refresh_token).toBe(true);
    expect(w.requests.length).toBe(1);
    noEnds(a);
  });
});
