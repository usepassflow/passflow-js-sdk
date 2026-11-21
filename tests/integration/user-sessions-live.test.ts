/**
 * The signed-in user's sessions against a running Passflow server.
 *
 * Opt-in: set INTEGRATION_TEST_SESSIONS_URL to the server's URL (for example a local server run
 * with cmd/config-mem.yaml) and, when it differs from the in-memory config's, INTEGRATION_TEST_MANAGEMENT_KEY.
 * Two `Passflow` instances with their own storage prefix stand for two devices of one user.
 */
import { describe, expect, test } from 'vitest';
import { Passflow } from '../../lib/passflow';
import { PassflowEvent } from '../../lib/store';
import { parseToken, TokenType } from '../../lib/token';

const url = process.env.INTEGRATION_TEST_SESSIONS_URL;
const managementKey = process.env.INTEGRATION_TEST_MANAGEMENT_KEY ?? 'test-management-key';

async function createPasswordApp(): Promise<string> {
  const response = await fetch(`${url}/management/apps/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Passflow-Key': managementKey },
    body: JSON.stringify({
      name: `sdk-sessions-${Date.now()}`,
      type: 'spa',
      active: true,
      offline: true,
      registration_allowed: true,
      redirect_urls: [window.location.origin],
      origins: [window.location.origin],
      auth_strategies: [{ type: 'internal', strategy: { identity: 'email', challenge: 'password', transport: 'none' } }],
    }),
  });
  expect(response.status).toBe(200);
  return (await response.json()).id;
}

function device(appId: string, prefix: string): Passflow {
  return new Passflow({
    url,
    appId,
    keyStoragePrefix: prefix,
    parseQueryParams: false,
    refreshCoordination: 'none',
    scopes: ['id', 'offline', 'email', 'openid'],
  });
}

function sidOf(passflow: Passflow): string | undefined {
  const access = passflow.getToken(TokenType.access_token);
  return access ? parseToken(access).sid : undefined;
}

describe.skipIf(!url)('user sessions against a live server', () => {
  test('list marks current, revoke-others ends the other device, revoking current signs out', async () => {
    const appId = await createPasswordApp();
    const email = `sessions-${Date.now()}@example.com`;
    const password = 'Str0ng!Passw0rd#';

    const a = device(appId, 'device-a');
    const b = device(appId, 'device-b');
    await a.signUp({ user: { email, password } });
    await b.signIn({ email, password });

    const aSid = sidOf(a);
    const bAccess = b.getToken(TokenType.access_token);
    expect(aSid).toBeTruthy();
    expect(bAccess).toBeTruthy();

    const listed = await a.listSessions();
    expect(listed).toHaveLength(2);
    expect(listed.filter((s) => s.current).map((s) => s.id)).toEqual([aSid]);

    const { revoked } = await a.signOutOtherSessions();
    expect(revoked).toBe(1);

    const bAfter = await fetch(`${url}/user/sessions`, {
      headers: { Authorization: `Bearer ${bAccess}`, 'X-Passflow-ClientID': appId },
    });
    expect(bAfter.status).toBe(401);

    const remaining = await a.listSessions();
    expect(remaining.map((s) => s.id)).toEqual([aSid]);

    await expect(a.revokeSession('no-such-session')).rejects.toBeTruthy();
    expect(a.getToken(TokenType.access_token)).toBeTruthy();

    let signOuts = 0;
    a.subscribe(
      {
        onAuthChange: () => {
          signOuts += 1;
        },
      },
      [PassflowEvent.SignOut],
    );
    await a.revokeSession(aSid as string);
    expect(a.getToken(TokenType.access_token)).toBeUndefined();
    expect(a.isAuthenticated()).toBe(false);
    expect(signOuts).toBe(1);
  }, 30_000);
});
