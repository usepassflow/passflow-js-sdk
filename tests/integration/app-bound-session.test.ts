import { beforeEach, describe, expect, test } from 'vitest';
import { Passflow } from '../../lib/passflow';
import { TEST_CONFIG, VALID_TOKENS } from '../helpers/fixtures';

describe("another app's session on the same origin", () => {
  beforeEach(() => localStorage.clear());

  test('does not count as signed in when only the app id changes', () => {
    const first = new Passflow(TEST_CONFIG);
    first.setTokens(VALID_TOKENS);
    expect(first.isAuthenticated()).toBe(true);

    const other = new Passflow({ ...TEST_CONFIG, appId: 'another-app' });
    expect(other.isAuthenticated()).toBe(false);
    expect(other.getParsedTokens()).toBeUndefined();
  });

  test('setAppId to another app drops the session the instance holds', async () => {
    const sdk = new Passflow(TEST_CONFIG);
    sdk.setTokens(VALID_TOKENS);
    sdk.setAppId('another-app');
    expect(await sdk.getTokens()).toBeUndefined();
    expect(sdk.isAuthenticated()).toBe(false);
  });
});
