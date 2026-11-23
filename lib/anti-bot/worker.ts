/**
 * The anti-bot worker entry, built on its own to `dist/anti-bot-worker.js` as one classic script.
 * `lib/index.ts` never imports it.
 *
 * @module anti-bot/worker
 */

import { handleSolveMessage, type PowSolveRequest } from './pow';

// Typed by hand: the "WebWorker" lib clashes with "DOM".
type WorkerScope = {
  onmessage: ((event: MessageEvent<PowSolveRequest>) => void) | null;
  postMessage(message: unknown): void;
};

const scope = self as unknown as WorkerScope;

scope.onmessage = (event) => {
  handleSolveMessage(event.data).then((response) => scope.postMessage(response));
};
