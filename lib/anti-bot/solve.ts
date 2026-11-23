/**
 * Solves a built-in anti-bot challenge in a Web Worker, or on the main thread when no worker URL
 * is set, and encodes the answer as the `X-Passflow-Anti-Bot` value.
 *
 * @module anti-bot/solve
 */

import { ANTI_BOT_SOLVE_FAILED_ERROR_ID, type AntiBotChallenge, type AntiBotSolution, PassflowError } from '../api/model';
import { findNumber, type PowSolveRequest, type PowSolveResponse, PowTimeoutError } from './pow';

const SOLVE_FAILED_MESSAGE = 'The browser check could not be completed. Try again later.';
const VERIFICATION_FAILED_MESSAGE = 'Verification failed. Try again.';

/** The largest `max` solved. The server's hardest challenge is far below it; anything above is refused unsolved. */
export const MAX_CHALLENGE_NUMBER = 5_000_000;

/** A solve still running after this long is stopped. */
export const SOLVE_TIMEOUT_MS = 60_000;

class SolveTimeoutError extends Error {}

/** A client-side anti-bot failure, shaped like the errors the API answers with. */
export const antiBotError = (id: string, message: string, location: string, cause?: unknown): PassflowError =>
  new PassflowError(
    { id, message, status: 0, location, time: new Date().toISOString() },
    cause === undefined ? undefined : { cause },
  );

/**
 * Runs the solve in a classic worker loaded from `workerUrl`, a same-origin file. A worker that
 * fails to load is not replaced by a main-thread solve: a wrong URL is a configuration error.
 */
const solveInWorker = (workerUrl: string, request: PowSolveRequest): Promise<number | null> =>
  new Promise((resolve, reject) => {
    const worker = new Worker(workerUrl);
    const timer = setTimeout(() => finish(() => reject(new SolveTimeoutError())), SOLVE_TIMEOUT_MS);
    const finish = (settle: () => void) => {
      clearTimeout(timer);
      worker.terminate();
      settle();
    };
    worker.addEventListener('message', (event: MessageEvent<PowSolveResponse>) => {
      const response = event.data;
      if (response && 'error' in response) {
        finish(() => reject(new Error(response.error)));
        return;
      }
      finish(() => resolve(response?.number ?? null));
    });
    worker.addEventListener('error', () => finish(() => reject(new Error('Anti-bot worker failed'))));
    worker.addEventListener('messageerror', () => finish(() => reject(new Error('Anti-bot worker message failed'))));
    worker.postMessage(request);
  });

/**
 * The number that answers `challenge`. Rejects with a `PassflowError` whose id is
 * `ANTI_BOT_SOLVE_FAILED_ERROR_ID` on an unknown algorithm, a worker error, missing Web Crypto,
 * or when no number in range matches.
 */
export async function solveChallenge(challenge: AntiBotChallenge, workerUrl?: string, location = 'anti-bot'): Promise<number> {
  if (challenge.algorithm !== 'SHA-256') {
    throw antiBotError(ANTI_BOT_SOLVE_FAILED_ERROR_ID, SOLVE_FAILED_MESSAGE, location);
  }
  if (!Number.isSafeInteger(challenge.max) || challenge.max < 0 || challenge.max > MAX_CHALLENGE_NUMBER) {
    throw antiBotError(ANTI_BOT_SOLVE_FAILED_ERROR_ID, VERIFICATION_FAILED_MESSAGE, location);
  }
  const request: PowSolveRequest = { salt: challenge.salt, challenge: challenge.challenge, max: challenge.max };
  let found: number | null;
  try {
    found =
      workerUrl && typeof Worker !== 'undefined'
        ? await solveInWorker(workerUrl, request)
        : await findNumber(request.salt, request.challenge, request.max, Date.now() + SOLVE_TIMEOUT_MS);
  } catch (error) {
    const message =
      error instanceof SolveTimeoutError || error instanceof PowTimeoutError
        ? VERIFICATION_FAILED_MESSAGE
        : SOLVE_FAILED_MESSAGE;
    throw antiBotError(ANTI_BOT_SOLVE_FAILED_ERROR_ID, message, location, error);
  }
  if (found === null) {
    throw antiBotError(ANTI_BOT_SOLVE_FAILED_ERROR_ID, SOLVE_FAILED_MESSAGE, location);
  }
  return found;
}

/** `base64(JSON {app, exp, max, salt, challenge, number, signature})`, keys in exactly that order. */
export function encodeSolution(challenge: AntiBotChallenge, number: number): string {
  const solution: AntiBotSolution = {
    app: challenge.app,
    exp: challenge.exp,
    max: challenge.max,
    salt: challenge.salt,
    challenge: challenge.challenge,
    number,
    signature: challenge.signature,
  };
  return btoa(JSON.stringify(solution));
}
