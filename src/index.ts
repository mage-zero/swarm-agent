import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { startStatusReporter } from './status.js';

const port = Number(process.env.PORT ?? 8080);

startStatusReporter();

serve({
  fetch: createApp().fetch,
  port,
});

// Minimal boot log for operators.
console.log(`swarm-agent listening on :${port}`);
