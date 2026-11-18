/**
 * Adds the signed-in user's access token to a request bound for an allowed origin, for `withAuth`
 * (fetch) and for `attachAuth` / `createClient` (axios). One rule for all of them:
 *
 * - Allowed means the page's own origin (`location.origin`) or one the developer listed, compared
 *   exactly as scheme, host and port: no prefix or substring match. A relative URL resolves against
 *   the page.
 * - A request that already carries an `Authorization` header goes out untouched, and so does one to
 *   any other origin, or one sent with no access token (signed out, a failed refresh, or a cookie or
 *   BFF session, which keeps no access token in the page).
 */

import type { FetchLike } from './replay';

/** What `withAuth`, `attachAuth` and `createClient` accept. */
export type WithAuthOptions = {
  /**
   * Origins besides the page's own that receive the access token, for example
   * `['https://api.example.com']`. Each entry is reduced to its origin; anything that is not a URL
   * throws when the wrapper or interceptor is built.
   */
  origins?: readonly string[];
};

/** Reads the access token, refreshed first when it has expired, or `undefined`. */
export type AccessTokenReader = () => Promise<string | undefined>;

/** The page's origin, or `undefined` outside a browser page (SSR, React Native, an opaque origin). */
const pageOrigin = (): string | undefined => {
  const origin = typeof location === 'undefined' ? undefined : location.origin;
  return origin && origin !== 'null' ? origin : undefined;
};

/**
 * The token to send with a request to `url` that has, or has not, its own `Authorization` header:
 * the shared decision behind every surface.
 */
export const createTokenDecision = (readAccessToken: AccessTokenReader, options?: WithAuthOptions) => {
  const listed = (options?.origins ?? []).map((origin) => new URL(origin).origin);

  return (url: string, hasAuthorization: boolean): Promise<string | undefined> => {
    if (hasAuthorization) return Promise.resolve(undefined);
    const page = pageOrigin();
    let origin: string;
    try {
      origin = new URL(url, page).origin;
    } catch {
      return Promise.resolve(undefined);
    }
    if (origin !== page && !listed.includes(origin)) return Promise.resolve(undefined);
    return readAccessToken();
  };
};

const isRequest = (input: RequestInfo | URL): input is Request => typeof Request !== 'undefined' && input instanceof Request;

/**
 * The headers the request will go out with. As in `fetch`, `init.headers` replaces a `Request`'s
 * own headers when it is given.
 */
const outgoingHeaders = (input: RequestInfo | URL, init: RequestInit | undefined): Headers =>
  new Headers(init?.headers !== undefined ? init.headers : isRequest(input) ? input.headers : undefined);

export const withAccessToken = (next: FetchLike, readAccessToken: AccessTokenReader, options?: WithAuthOptions): FetchLike => {
  const decide = createTokenDecision(readAccessToken, options);

  return async (input, init) => {
    const url = isRequest(input) ? input.url : input instanceof URL ? input.href : String(input);
    const headers = outgoingHeaders(input, init);
    const token = await decide(url, headers.has('authorization'));
    if (!token) return next(input, init);

    headers.set('authorization', `Bearer ${token}`);
    return next(input, { ...init, headers });
  };
};

/** The subset of an axios request config the request interceptor reads and writes. */
type AxiosRequestLike = { url?: string; baseURL?: string; headers?: unknown };

type HeaderBag = {
  has?: (name: string) => boolean;
  set?: (name: string, value: string) => unknown;
  [name: string]: unknown;
};

/** The request's full URL, joined from `baseURL` and `url` as axios does. */
const axiosUrl = (config: AxiosRequestLike): string => {
  const url = config.url ?? '';
  if (!config.baseURL || /^([a-z][a-z\d+\-.]*:)?\/\//i.test(url)) return url;
  return url ? `${config.baseURL.replace(/\/+$/, '')}/${url.replace(/^\/+/, '')}` : config.baseURL;
};

const hasAuthorizationHeader = (headers: HeaderBag | undefined): boolean => {
  if (!headers) return false;
  if (typeof headers.has === 'function') return headers.has('Authorization');
  return Object.keys(headers).some((name) => name.toLowerCase() === 'authorization' && headers[name] != null);
};

/** An axios request interceptor that adds the access token under the same rule as `withAccessToken`. */
export const axiosAccessTokenInterceptor = (readAccessToken: AccessTokenReader, options?: WithAuthOptions) => {
  const decide = createTokenDecision(readAccessToken, options);

  return async <T extends AxiosRequestLike>(config: T): Promise<T> => {
    const headers = config.headers as HeaderBag | undefined;
    const token = await decide(axiosUrl(config), hasAuthorizationHeader(headers));
    if (!token) return config;

    const value = `Bearer ${token}`;
    if (headers && typeof headers.set === 'function') {
      headers.set('Authorization', value);
    } else {
      config.headers = { ...(headers ?? {}), Authorization: value };
    }
    return config;
  };
};
