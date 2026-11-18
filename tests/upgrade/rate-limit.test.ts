import { describe, expect, test } from 'vitest';
import { classifyUpgradeError } from '../../lib/upgrade/errors';

/** A raw AxiosError as the hosted rounds reject on a 429 from the verify limiter. */
const rateLimited = (headers: Record<string, string> = { 'retry-after': '120' }) =>
  Object.assign(new Error('Request failed with status code 429'), {
    response: {
      status: 429,
      headers,
      data: {
        error: {
          id: 'error.2fa.rate_limit_exceeded',
          message: 'Too many attempts. Please try again later.',
          status: 429,
          time: '2026-11-19T00:00:00Z',
        },
      },
    },
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
      expect(error.message).toBe('Too many attempts. Please try again later.');
      expect(error.errorId).toBe('error.2fa.rate_limit_exceeded');
    },
  );

  test('the plain-text body older servers send is still a rate limit, with Retry-After from the header', () => {
    const error = classifyUpgradeError(
      Object.assign(new Error('Request failed with status code 429'), {
        response: {
          status: 429,
          headers: { 'retry-after': '60' },
          data: { error: 'localized error: error.2fa.rate_limit_exceeded. Details: [].' },
        },
      }),
      'refresh',
    );

    expect(error.kind).toBe('rate_limited');
    expect(error.retryable).toBe(false);
    expect(error.retryAfter).toBe(60);
    // That text is the server's internal error string, not one to show a user.
    expect(error.message).toBe('Too many requests. Try again later.');
  });

  test('a 503 from an unavailable limiter store is a server error, not a rate limit', () => {
    const error = classifyUpgradeError(
      Object.assign(new Error('Request failed with status code 503'), {
        response: {
          status: 503,
          headers: {},
          data: { error: { id: 'error.rate_limit.unavailable', message: 'Service unavailable.', status: 503 } },
        },
      }),
      'refresh',
    );

    const plain503 = classifyUpgradeError(
      Object.assign(new Error('Request failed with status code 503'), {
        response: { status: 503, headers: {}, data: {} },
      }),
      'refresh',
    );
    expect(error.kind).not.toBe('rate_limited');
    expect(error.kind).toBe(plain503.kind);
    expect(error.retryable).toBe(plain503.retryable);
    expect(error.status).toBe(503);
  });

  test('without a usable Retry-After, retryAfter is absent and the message falls back to the default', () => {
    const error = classifyUpgradeError(
      Object.assign(new Error('Request failed with status code 429'), { response: { status: 429, headers: {}, data: {} } }),
      'start',
    );

    expect(error.kind).toBe('rate_limited');
    expect(error.retryAfter).toBeUndefined();
    expect(error.message).toBe('Too many requests. Try again later.');
  });

  test("a 429 in the Passflow error envelope uses the envelope's message and id", () => {
    const error = classifyUpgradeError(
      Object.assign(new Error('Request failed with status code 429'), {
        response: {
          status: 429,
          headers: { 'retry-after': '30' },
          data: { error: { id: 'error.api.rate_limit.exceeded', message: 'Too many refresh requests.', status: 429 } },
        },
      }),
      'refresh',
    );

    expect(error.kind).toBe('rate_limited');
    expect(error.message).toBe('Too many refresh requests.');
    expect(error.errorId).toBe('error.api.rate_limit.exceeded');
    expect(error.retryAfter).toBe(30);
  });
});
