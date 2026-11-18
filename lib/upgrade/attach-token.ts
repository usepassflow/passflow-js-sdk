/**
 * Adds the signed-in user's access token to a request bound for an allowed origin.
 *
 * Allowed means the page's own origin (`location.origin`) or one the developer listed, compared
 * exactly as scheme, host and port: no prefix or substring match. A relative URL resolves against
 * the page. A request that already carries an `Authorization` header goes out untouched, and so does
 * one to any other origin, or one sent with no signed-in user.
 */

import type { FetchLike } from './replay';

/** What `withAuth(fetch, options)` accepts. */
export type WithAuthOptions = {
  /**
   * Origins besides the page's own that receive the access token, for example
   * `['https://api.example.com']`. Each entry is reduced to its origin; anything that is not a URL
   * throws when the wrapper is built.
   */
  origins?: readonly string[];
};

/** The page's origin, or `undefined` outside a browser page (SSR, React Native, an opaque origin). */
const pageOrigin = (): string | undefined => {
  const origin = typeof location === 'undefined' ? undefined : location.origin;
  return origin && origin !== 'null' ? origin : undefined;
};

const isRequest = (input: RequestInfo | URL): input is Request => typeof Request !== 'undefined' && input instanceof Request;

const originOf = (input: RequestInfo | URL, base: string | undefined): string | undefined => {
  const url = isRequest(input) ? input.url : input instanceof URL ? input.href : String(input);
  try {
    return new URL(url, base).origin;
  } catch {
    return undefined;
  }
};

/**
 * The headers the request will go out with. As in `fetch`, `init.headers` replaces a `Request`'s
 * own headers when it is given.
 */
const outgoingHeaders = (input: RequestInfo | URL, init: RequestInit | undefined): Headers =>
  new Headers(init?.headers !== undefined ? init.headers : isRequest(input) ? input.headers : undefined);

export const withAccessToken = (
  next: FetchLike,
  readAccessToken: () => Promise<string | undefined>,
  options?: WithAuthOptions,
): FetchLike => {
  const listed = (options?.origins ?? []).map((origin) => new URL(origin).origin);

  return async (input, init) => {
    const page = pageOrigin();
    const origin = originOf(input, page);
    if (!origin || (origin !== page && !listed.includes(origin))) {
      return next(input, init);
    }

    const headers = outgoingHeaders(input, init);
    if (headers.has('authorization')) {
      return next(input, init);
    }

    const token = await readAccessToken();
    if (!token) {
      return next(input, init);
    }

    headers.set('authorization', `Bearer ${token}`);
    return next(input, { ...init, headers });
  };
};
