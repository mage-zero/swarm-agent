import { Hono } from 'hono';
import { getHealthStatus } from './health.js';
import { buildStatusPayload, handleJoinTokenRequest } from './status.js';

export const createApp = () => {
  const app = new Hono();

  app.get('/health', (c) => c.json(getHealthStatus()));

  app.get('/join-token', async (c) => {
    const secret = c.req.header('x-mz-join-secret');
    const result = await handleJoinTokenRequest(secret);
    return c.json(result.body, result.status);
  });

  app.get('/', async (c) => {
    const host = (c.req.header('host') || '').split(':')[0];
    const wantsJson =
      c.req.query('format') === 'json' ||
      (c.req.header('accept') || '').includes('application/json');
    const result = await buildStatusPayload(host, wantsJson);
    return result.type === 'json' ? c.json(result.payload) : c.html(result.payload);
  });

  return app;
};
