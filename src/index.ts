import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { ensureCloudSwarmDeployKey } from './deploy.js';
import { startDeploymentWorker } from './deploy-worker.js';
import { startEnvironmentSync } from './env-sync.js';
import { startStatusReporter } from './status.js';

const port = Number(process.env.PORT ?? 8080);

startStatusReporter();
startEnvironmentSync();
void ensureCloudSwarmDeployKey();
startDeploymentWorker();

serve({
  fetch: createApp().fetch,
  port,
});

// Minimal boot log for operators.
console.log(`swarm-agent listening on :${port}`);
