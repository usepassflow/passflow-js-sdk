/**
 * The built-in anti-bot proof of work: find the number behind a SHA-256 challenge.
 *
 * This module imports nothing, so the worker bundle (`worker.ts`) holds only this file.
 *
 * @module anti-bot/pow
 */

export type PowSolveRequest = { salt: string; challenge: string; max: number };
export type PowSolveResponse = { number: number | null } | { error: string };

/** Digests started together; enough to make the per-call cost of the async digest small. */
const BATCH_SIZE = 256;

const HEX = Array.from({ length: 256 }, (_, byte) => byte.toString(16).padStart(2, '0'));

const toHex = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  let hex = '';
  for (const byte of bytes) hex += HEX[byte] as string;
  return hex;
};

/** Thrown by `findNumber` when it passes its deadline. */
export class PowTimeoutError extends Error {}

/**
 * Smallest n in [0, max] with hex(SHA-256(salt + ":" + n)) === challenge, or null. Throws
 * `PowTimeoutError` once `deadline` (a `Date.now()` value) has passed.
 */
export async function findNumber(
  salt: string,
  challenge: string,
  max: number,
  deadline = Number.POSITIVE_INFINITY,
): Promise<number | null> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('Web Crypto unavailable');
  }
  const target = challenge.toLowerCase();
  const encoder = new TextEncoder();

  for (let start = 0; start <= max; start += BATCH_SIZE) {
    if (Date.now() > deadline) {
      throw new PowTimeoutError('Solve timed out');
    }
    const end = Math.min(start + BATCH_SIZE - 1, max);
    const digests: Promise<ArrayBuffer>[] = [];
    for (let n = start; n <= end; n++) {
      digests.push(subtle.digest('SHA-256', encoder.encode(`${salt}:${n}`)));
    }
    const hashes = await Promise.all(digests);
    for (let i = 0; i < hashes.length; i++) {
      if (toHex(hashes[i] as ArrayBuffer) === target) return start + i;
    }
  }
  return null;
}

/** The worker's message handler, exported so the worker file stays a few lines. */
export async function handleSolveMessage(request: PowSolveRequest): Promise<PowSolveResponse> {
  try {
    return { number: await findNumber(request.salt, request.challenge, request.max) };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}
