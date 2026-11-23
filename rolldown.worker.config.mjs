// Builds the anti-bot worker as ONE classic script (no `import`, no `export`), apart from the
// library build: a second Vite entry could move `pow.ts` into a shared chunk the worker cannot load.
// Apps serve the file from their own origin and pass its URL as `antiBotWorkerUrl`.
import { defineConfig } from 'rolldown';

export default defineConfig({
  input: 'lib/anti-bot/worker.ts',
  output: { file: 'dist/anti-bot-worker.js', format: 'iife', minify: true, sourcemap: false },
});
