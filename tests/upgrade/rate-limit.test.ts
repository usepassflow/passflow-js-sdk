import { describe, expect, test } from 'vitest';
import { classifyUpgradeError } from '../../lib/upgrade/errors';

/** A raw AxiosError as the hosted rounds reject on a 429 from the verify limiter. */
const rateLimited = (headers: Record<string, string> = { 'retry-after': '120' }) =>
  Object.assign(new Error('Request failed with status code 429'), {
    response: { status: 429, headers, data: { error: 'Too many verification attempts. Try again later.' } },
  });

describe('a 429 on either step-up round', () => {
  test.each(['start', 'refresh'] as const)(
    'on %s it is a terminal rate limit carrying Retry-After and the server text',
    (endpoint) => {
      const error = classifyUpgradeError(rateLimited(), endpoint);

      expect(error.kind).toBe('rate_limited');
      expect(error.retryable).toBe(false);
      expect(error.status).toBe(429);
      expect(error.retryAfter).toBe(120);
      expect(error.message).toBe('Too many verification attempts. Try again later.');
    },
  );

  test('without a usable Retry-After, retryAfter is absent and the message falls back to the default', () => {
    const error = classifyUpgradeError(
      Object.assign(new Error('Request failed with status code 429'), { response: { status: 429, headers: {}, data: {} } }),
      'start',
    );

    expect(error.kind).toBe('rate_limited');
    expect(error.retryAfter).toBeUndefined();
    expect(error.message).toBe('Too many requests. Try again later.');
  });
});
