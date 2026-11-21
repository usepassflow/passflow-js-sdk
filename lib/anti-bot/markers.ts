/**
 * The per-request config marker of a covered sign-in call. It imports nothing at runtime, so the
 * axios client can read it without an import cycle.
 *
 * @module anti-bot/markers
 */

import type { AxiosRequestConfig } from 'axios';
import type { AntiBotOperation } from './types';

/** Config key marking a covered request. Never sent on the wire. */
const ANTI_BOT_MARKER = '__passflowAntiBot';

/**
 * Axios copies this object into each request's config (and each resend's), so the interceptors
 * may write `builtin` and `retried` on it.
 */
export type AntiBotMark = {
  operation: AntiBotOperation;
  identifier?: string;
  /** Set by the request interceptor: the value came from the built-in check. */
  builtin?: boolean;
  /** Set by the response interceptor before the one resend after `anti_bot.failed`. */
  retried?: boolean;
};

/** Request config that marks a call as covered by the anti-bot check. */
export const withAntiBot = (operation: AntiBotOperation, identifier?: string): AxiosRequestConfig => {
  const mark: AntiBotMark = identifier ? { operation, identifier } : { operation };
  return { [ANTI_BOT_MARKER]: mark } as AxiosRequestConfig;
};

export const readAntiBotMark = (config: unknown): AntiBotMark | undefined => {
  if (typeof config !== 'object' || config === null) return undefined;
  const mark = (config as Record<string, unknown>)[ANTI_BOT_MARKER];
  return typeof mark === 'object' && mark !== null ? (mark as AntiBotMark) : undefined;
};
