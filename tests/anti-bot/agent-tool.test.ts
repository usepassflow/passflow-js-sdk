/**
 * { agentTool: true } adds X-Passflow-Agent-Tool: 1, and only then.
 */
import { describe, expect, test } from 'vitest';
import { AGENT_TOOL_HEADER_KEY } from '../../lib/index';
import {
  AGENT_TOOL,
  attempt,
  BOT_FRIENDLY,
  CHALLENGE_PATH,
  COVERED,
  federatedPayload,
  HUMAN_BUILTIN,
  harness,
  header,
  until,
} from './harness';

describe('agentTool option', () => {
  test('REQ-8 the header name is X-Passflow-Agent-Tool', () => {
    expect(AGENT_TOOL_HEADER_KEY).toBe('X-Passflow-Agent-Tool');
  });

  test.each(COVERED)('REQ-8 $name with agentTool: $route has the header "1"; the challenge does not', async (c) => {
    const h = harness(HUMAN_BUILTIN);
    await c.run(h, { agentTool: true });
    expect(header(h.wire(c.route)[0], AGENT_TOOL)).toBe('1');
    for (const r of h.wire(CHALLENGE_PATH)) expect(header(r, AGENT_TOOL)).toBeUndefined();
  });

  test.each(COVERED)('REQ-8 $name without the option: no agent-tool header on any request', async (c) => {
    const h = harness(HUMAN_BUILTIN);
    await c.run(h);
    for (const r of h.requests) expect(header(r, AGENT_TOOL), r.path).toBeUndefined();
  });

  test('REQ-8 passwordless complete with agentTool has the header', async () => {
    const h = harness(HUMAN_BUILTIN);
    await attempt(h.sdk.passwordlessSignInComplete({ challenge_id: 'pl-1', otp: '123456' } as never, { agentTool: true }));
    expect(header(h.wire('/auth/passwordless/complete')[0], AGENT_TOOL)).toBe('1');
  });

  test('REQ-8 PKCE sign-in with agentTool: login has it, pkce_exchange does not', async () => {
    const h = harness({ ...HUMAN_BUILTIN, pkce_enabled: true });
    h.reply('/auth/login', { code: 'authz-code' });
    await attempt(h.sdk.signIn({ email: 'qa@example.com', password: 'Password123!' } as never, { agentTool: true }));
    expect(header(h.wire('/auth/login')[0], AGENT_TOOL)).toBe('1');
    expect(h.wire('/auth/pkce_exchange')).toHaveLength(1);
    expect(header(h.wire('/auth/pkce_exchange')[0], AGENT_TOOL)).toBeUndefined();
  });

  test('REQ-8 bot_friendly + agentTool: federated takes the POST path, with the agent header and no anti-bot', async () => {
    const h = harness(BOT_FRIENDLY);
    h.sdk.federatedAuthWithRedirect(federatedPayload() as never, { agentTool: true });
    await until(() => h.navigations.length > 0);
    const [start] = h.wire('/auth/federated/start/google');
    expect(start?.method).toBe('POST');
    expect(header(start, AGENT_TOOL)).toBe('1');
    expect(header(start, 'X-Passflow-Anti-Bot')).toBeUndefined();
    expect(h.wire(CHALLENGE_PATH)).toHaveLength(0);
  });
});
