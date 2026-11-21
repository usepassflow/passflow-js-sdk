/**
 * Decides whether a covered call needs an anti-bot value, and produces it.
 *
 * Only a `human_only` app gets a value. A `bot_friendly` app, an app whose settings do not report
 * a bot mode, and a failed or absent settings read all get none: no challenge is fetched, no event
 * fires, and the request goes out as it always has.
 *
 * Errors are thrown here and never reported here: the covered method's own `catch` reports one
 * `Error` with its own `operation`.
 *
 * @module anti-bot/anti-bot
 */

import {
  ANTI_BOT_PROVIDER_FAILED_ERROR_ID,
  ANTI_BOT_PROVIDER_MISSING_ERROR_ID,
  type AntiBotChallenge,
  type AntiBotProviderName,
} from '../api/model';
import { ANTI_BOT_ACTION } from '../constants';
import { PassflowEvent, type PassflowStore } from '../store';
import { antiBotError, encodeSolution, solveChallenge } from './solve';
import type { AntiBotAppSettings, AntiBotDeviceContext, AntiBotTokenProvider, AntiBotTokenRequest } from './types';

export type AntiBotDeps = {
  /** This app's settings; `undefined` while there is no app id. */
  readSettings: () => Promise<AntiBotAppSettings | undefined>;
  fetchChallenge: (request: { identifier?: string; device?: AntiBotDeviceContext }) => Promise<AntiBotChallenge>;
  store: Pick<PassflowStore, 'notify'>;
  workerUrl?: string;
};

/** A value for `X-Passflow-Anti-Bot`; `builtin` tells whether a `failed` answer may be resent once. */
export type AntiBotHeader = { value: string; builtin: boolean };

export type AntiBot = {
  setTokenProvider(provider: AntiBotTokenProvider | undefined): void;
  /** `undefined`: send no header (not `human_only`, no app id, settings unreadable). */
  headerFor(request: AntiBotTokenRequest): Promise<AntiBotHeader | undefined>;
};

const PROVIDER_MISSING_MESSAGE = 'This app requires a verification token. Call setAntiBotTokenProvider() before signing in.';
const PROVIDER_FAILED_MESSAGE = 'The verification could not be completed. Try again.';

export function createAntiBot(deps: AntiBotDeps): AntiBot {
  let tokenProvider: AntiBotTokenProvider | undefined;

  const providerToken = async (provider: AntiBotTokenProvider, request: AntiBotTokenRequest): Promise<string> => {
    let token: string;
    try {
      token = await provider({ action: ANTI_BOT_ACTION, operation: request.operation });
    } catch (error) {
      throw antiBotError(ANTI_BOT_PROVIDER_FAILED_ERROR_ID, PROVIDER_FAILED_MESSAGE, request.operation, error);
    }
    if (typeof token !== 'string' || token === '') {
      throw antiBotError(ANTI_BOT_PROVIDER_FAILED_ERROR_ID, PROVIDER_FAILED_MESSAGE, request.operation);
    }
    return token;
  };

  const builtinValue = async (request: AntiBotTokenRequest): Promise<string> => {
    const challenge = await deps.fetchChallenge({
      ...(request.identifier ? { identifier: request.identifier } : {}),
      ...(request.device ? { device: request.device } : {}),
    });
    const number = await solveChallenge(challenge, deps.workerUrl, request.operation);
    return encodeSolution(challenge, number);
  };

  return {
    setTokenProvider(provider) {
      tokenProvider = provider;
    },

    async headerFor(request) {
      const settings = request.settings ?? (await deps.readSettings().catch(() => undefined));
      // The bot-friendly guarantee: anything but a known human_only app sends what it sends today.
      if (settings?.bot_mode !== 'human_only') {
        return undefined;
      }
      const provider: AntiBotProviderName = settings.anti_bot?.provider ?? 'builtin';
      const builtin = provider === 'builtin';

      deps.store.notify(PassflowEvent.AntiBotSolving, { operation: request.operation, provider });
      let value: string;
      if (builtin) {
        value = await builtinValue(request);
      } else {
        const byo = tokenProvider;
        if (!byo) {
          throw antiBotError(ANTI_BOT_PROVIDER_MISSING_ERROR_ID, PROVIDER_MISSING_MESSAGE, request.operation);
        }
        value = await providerToken(byo, request);
      }
      deps.store.notify(PassflowEvent.AntiBotSolved, { operation: request.operation, provider });
      return { value, builtin };
    },
  };
}
