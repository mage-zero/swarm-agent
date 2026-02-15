import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { ensureCloudSwarmDeployKey } from './deploy.js';
import { startAddonWorker } from './addon-worker.js';
import { startDeploymentWorker } from './deploy-worker.js';
import { startEnvironmentSync } from './env-sync.js';
import { startInspectionScheduler, startStatusReporter, startTuningScheduler } from './status.js';
import { startMeshSyncScheduler } from './mesh.js';
import { startUpgradeScheduler } from './upgrade.js';

const port = Number(process.env.PORT ?? 8080);

startStatusReporter();
startTuningScheduler();
startInspectionScheduler();
startMeshSyncScheduler();
startEnvironmentSync();
void ensureCloudSwarmDeployKey();
startDeploymentWorker();
startAddonWorker();
startUpgradeScheduler();

serve({
  fetch: createApp().fetch,
  port,
});

// Minimal boot log for operators.
console.log(`swarm-agent listening on :${port}`);
