import { Hono } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { getHealthStatus } from './health.js';
import { handleDeployAddon, handleDeployArtifact, handleDeployKey } from './deploy.js';
import { handleDeployProgress, handleRunbookProgress } from './deploy-progress.js';
import {
  buildCapacityPayload,
  buildPlannerPayload,
  buildServiceStatusPayload,
  buildStatusPayload,
  handleJoinTokenRequest,
  handleNodeRemovalRequest,
  handleTuningApprovalRequest,
} from './status.js';
import { handleMeshJoinRequest } from './mesh.js';
import { handleDeployLogsBundle } from './deploy-logs.js';
import { executeRunbook, handleServiceRestart, listRunbooks } from './support-runbooks.js';
import { cleanupOrphanedRunbookJobs } from './swarm.js';
import { handleMonitoringDashboardsBootstrap } from './monitoring-dashboards.js';
import { Readable } from 'stream';

export const createApp = () => {
  const app = new Hono();

  app.get('/health', (c) => c.json(getHealthStatus()));

  app.get('/join-token', async (c) => {
    const secret = c.req.header('x-mz-join-secret');
    const result = await handleJoinTokenRequest(secret);
    return c.json(result.body, result.status as ContentfulStatusCode);
  });

  app.post('/deploy/artifact', async (c) => {
    const result = await handleDeployArtifact(c);
    return c.json(result.body, result.status as ContentfulStatusCode);
  });

  app.post('/deploy/addon', async (c) => {
    const result = await handleDeployAddon(c);
    return c.json(result.body, result.status as ContentfulStatusCode);
  });

  app.post('/deploy/cloud-swarm-key', async (c) => {
    const result = await handleDeployKey(c);
    return c.json(result.body, result.status as ContentfulStatusCode);
  });

  app.get('/v1/capacity', async (c) => {
    const payload = await buildCapacityPayload();
    return c.json(payload);
  });

  app.get('/v1/planner', async (c) => {
    const payload = await buildPlannerPayload();
    return c.json(payload);
  });

  app.post('/v1/mesh/join', async (c) => {
    const request = c.req.raw ?? (c.req as unknown as Request);
    const result = await handleMeshJoinRequest(request);
    return c.json(result.body, result.status as ContentfulStatusCode);
  });

  app.post('/v1/tuning/approve', async (c) => {
    const request = c.req.raw ?? (c.req as unknown as Request);
    const result = await handleTuningApprovalRequest(request);
    return c.json(result.body, result.status as ContentfulStatusCode);
  });

  app.post('/v1/swarm/nodes/remove', async (c) => {
    const request = c.req.raw ?? (c.req as unknown as Request);
    const result = await handleNodeRemovalRequest(request);
    return c.json(result.body, result.status as ContentfulStatusCode);
  });

  app.get('/v1/support/runbooks', async (c) => {
    const runbooks = await listRunbooks();
    return c.json({ runbooks });
  });

  app.post('/v1/support/runbook', async (c) => {
    const request = c.req.raw ?? (c.req as unknown as Request);
    const result = await executeRunbook(request);
    if ('error' in result) {
      return c.json({ error: result.error }, result.status as ContentfulStatusCode);
    }
    return c.json(result);
  });

  app.post('/v1/service/restart', async (c) => {
    const request = c.req.raw ?? (c.req as unknown as Request);
    const result = await handleServiceRestart(request);
    if (result.error) {
      return c.json({ error: result.error }, (result.status || 500) as ContentfulStatusCode);
    }
    return c.json(result);
  });

  app.post('/v1/monitoring/dashboards/bootstrap', async (c) => {
    const request = c.req.raw ?? (c.req as unknown as Request);
    const result = await handleMonitoringDashboardsBootstrap(request);
    return c.json(result.body, result.status as ContentfulStatusCode);
  });

  app.post('/v1/support/cleanup-jobs', async (c) => {
    const result = await cleanupOrphanedRunbookJobs();
    return c.json(result);
  });

  app.get('/v1/deploy/logs/:deploymentId/bundle', async (c) => {
    const result = await handleDeployLogsBundle(c);
    if ('body' in result) {
      return c.json(result.body, result.status as ContentfulStatusCode);
    }
    const stream = Readable.toWeb(result.stream) as unknown as ReadableStream;
    return new Response(stream, { status: result.status, headers: result.headers });
  });

  app.get('/v1/deploy/progress/:deploymentId', async (c) => {
    const result = await handleDeployProgress(c);
    return c.json(result.body, result.status as ContentfulStatusCode);
  });

  app.get('/v1/runbook/progress', async (c) => {
    const result = await handleRunbookProgress(c);
    return c.json(result.body, result.status as ContentfulStatusCode);
  });

  app.get('/v1/services', async (c) => {
    const environmentId = Number(c.req.query('environment_id') || 0);
    const payload = await buildServiceStatusPayload(environmentId || undefined);
    return c.json(payload);
  });

  app.get('/', async (c) => {
    const host = (c.req.header('host') || '').split(':')[0];
    const wantsJson =
      c.req.query('format') === 'json' ||
      (c.req.header('accept') || '').includes('application/json');
    const includes = (c.req.query('include') || '').split(',');
    const includeCapacity = includes.includes('capacity');
    const includePlanner = includes.includes('planner');
    const includeServices = includes.includes('services');
    const result = await buildStatusPayload(
      host,
      wantsJson,
      includeCapacity,
      includePlanner,
      includeServices,
    );
    return result.type === 'json' ? c.json(result.payload) : c.html(result.payload);
  });

  return app;
};
