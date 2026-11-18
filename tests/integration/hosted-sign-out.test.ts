/**
 * `logOut()` after a hosted sign-in also ends the hosted login's own session.
 *
 * The hosted login keeps a session cookie on the Passflow host, which only a top-level visit to
 * `/oidc/end_session` can end. After the local sign-out and its one `SignOut`, the page goes there
 * with `client_id`, the stored ID token as `id_token_hint`, and `post_logout_redirect_uri`: the
 * address the hosted sign-in landed on, or `options.postLogoutRedirectUri`. A session that did not
 * come from the hosted login never navigates.
 */
import { describe, expect, test } from 'vitest';
import { PassflowEvent } from '../../lib/index';
import { TEST_CONFIG, VALID_TOKENS } from '../helpers/fixtures';
import {
  landingUrl,
  type ModeClient,
  type ModeHarness,
  modeHarness,
  OIDC_CODE,
  PAGE,
  publishKey,
  SDK_APP,
  SIMPLE_APP,
  settle,
  startSdkSignIn,
  stubTokenEndpoint,
  tokenResponse,
} from '../helpers/oidc-harness';
import { until } from '../helpers/pkce-harness';
import { issuedTokens, tokenParams } from '../helpers/signed-tokens';

const END_SESSION = `${TEST_CONFIG.url}/oidc/end_session`;

async function signedIn(c: ModeClient) {
  await until(() => c.of(PassflowEvent.SignIn).length + c.of(PassflowEvent.Error).length > 0);
  await settle();
  expect(c.of(PassflowEvent.Error)).toEqual([]);
  expect(c.sdk.isAuthenticated()).toBe(true);
}

/** An SDK-mode hosted sign-in that landed and was redeemed in this tab. */
async function sdkModeSignIn(redirectUrl?: string) {
  const h = modeHarness(SDK_APP);
  h.reply('/user/logout', { status: 'ok' });
  const key = await publishKey(h);
  const starter = h.client();
  const { slot } = await startSdkSignIn(h, starter, redirectUrl ? { redirectUrl } : undefined);
  starter.sdk.dispose();
  const issued = await tokenResponse(key, { nonce: slot.nonce });
  stubTokenEndpoint({ status: 200, body: issued });
  h.land(landingUrl({ code: OIDC_CODE, state: slot.state }));
  const c = h.client({ parseQueryParams: true });
  await signedIn(c);
  return { h, c, slot, idToken: issued.id_token! };
}

/** A Simple-mode hosted sign-in: the hosted login returned the tokens in the URL. */
async function simpleModeSignIn() {
  const h = modeHarness(SIMPLE_APP);
  h.reply('/user/logout', { status: 'ok' });
  const tokens = await issuedTokens(await publishKey(h));
  h.land(`${PAGE}?keep=1#${tokenParams(tokens)}`);
  const c = h.client({ parseQueryParams: true });
  await signedIn(c);
  return { h, c, idToken: tokens.id_token };
}

async function logOut(h: ModeHarness, c: ModeClient, options?: { postLogoutRedirectUri?: string }) {
  const before = h.navigations.length;
  let navigationsAtSignOut = -1;
  c.sdk.subscribe(
    {
      onAuthChange: () => {
        navigationsAtSignOut = h.navigations.length;
      },
    },
    [PassflowEvent.SignOut],
  );
  await c.sdk.logOut(options);
  await settle();
  expect(c.of(PassflowEvent.SignOut)).toHaveLength(1);
  expect(c.sdk.isAuthenticated()).toBe(false);
  expect(h.wire('/user/logout')).toHaveLength(1);
  return { sent: h.navigations.slice(before), navigationsAtSignOut, before };
}

function expectEndSession(url: string, params: { idToken: string; redirect: string }) {
  const sent = new URL(url);
  expect(sent.origin + sent.pathname).toBe(END_SESSION);
  expect(sent.searchParams.get('client_id')).toBe(TEST_CONFIG.appId);
  expect(sent.searchParams.get('id_token_hint')).toBe(params.idToken);
  expect(sent.searchParams.get('post_logout_redirect_uri')).toBe(params.redirect);
}

describe('a hosted sign-in in SDK mode', () => {
  test('logOut ends the hosted session, returning to the redirect URI the sign-in used', async () => {
    const { h, c, slot, idToken } = await sdkModeSignIn();
    const { sent, navigationsAtSignOut, before } = await logOut(h, c);
    expect(sent).toHaveLength(1);
    expectEndSession(sent[0]!, { idToken, redirect: slot.redirectUri });
    // The local sign-out and its SignOut come first.
    expect(navigationsAtSignOut).toBe(before);
  });

  test('an explicit redirectUrl of the sign-in is where the user returns', async () => {
    const { h, c, idToken } = await sdkModeSignIn('https://app.example/registered');
    const { sent } = await logOut(h, c);
    expectEndSession(sent[0]!, { idToken, redirect: 'https://app.example/registered' });
  });

  test('options.postLogoutRedirectUri overrides the return address', async () => {
    const { h, c, idToken } = await sdkModeSignIn();
    const { sent } = await logOut(h, c, { postLogoutRedirectUri: 'https://app.example/bye' });
    expectEndSession(sent[0]!, { idToken, redirect: 'https://app.example/bye' });
  });

  test('a second logOut does not navigate again', async () => {
    const { h, c } = await sdkModeSignIn();
    await logOut(h, c);
    const before = h.navigations.length;
    await c.sdk.logOut();
    await settle();
    expect(h.navigations).toHaveLength(before);
  });
});

describe('a hosted sign-in in Simple mode', () => {
  test('logOut ends the hosted session, returning to the page the tokens landed on', async () => {
    const { h, c, idToken } = await simpleModeSignIn();
    const { sent } = await logOut(h, c);
    expect(sent).toHaveLength(1);
    expectEndSession(sent[0]!, { idToken, redirect: PAGE });
  });
});

describe('app code that throws during logOut', () => {
  test('a throwing SignOut subscriber does not keep the hosted session alive', async () => {
    const { h, c, slot, idToken } = await sdkModeSignIn();
    c.sdk.subscribe(
      {
        onAuthChange: () => {
          throw new Error('subscriber failed');
        },
      },
      [PassflowEvent.SignOut],
    );
    const before = h.navigations.length;
    await expect(c.sdk.logOut()).rejects.toThrow('subscriber failed');
    await settle();
    const sent = h.navigations.slice(before);
    expect(sent).toHaveLength(1);
    expectEndSession(sent[0]!, { idToken, redirect: slot.redirectUri });
  });

  test('a throwing expiredSession callback does not keep the hosted session alive', async () => {
    const { h, c, slot, idToken } = await sdkModeSignIn();
    await c.sdk.session({
      expiredSession: async () => {
        throw new Error('callback failed');
      },
    });
    const before = h.navigations.length;
    await expect(c.sdk.logOut()).rejects.toThrow('callback failed');
    await settle();
    const sent = h.navigations.slice(before);
    expect(sent).toHaveLength(1);
    expectEndSession(sent[0]!, { idToken, redirect: slot.redirectUri });
  });
});

describe('another app on the same storage', () => {
  test("logOut does not use the first app's hosted sign-in record", async () => {
    const { h } = await sdkModeSignIn();
    const other = h.client({ appId: 'another-app' });
    const before = h.navigations.length;
    await other.sdk.logOut();
    await settle();
    expect(h.navigations.slice(before)).toEqual([]);
  });
});

describe('a session that did not come from the hosted login', () => {
  test('logOut does not navigate', async () => {
    const h = modeHarness(SIMPLE_APP);
    h.reply('/user/logout', { status: 'ok' });
    const c = h.client();
    c.sdk.setTokens(VALID_TOKENS);
    const { sent } = await logOut(h, c);
    expect(sent).toEqual([]);
  });
});
