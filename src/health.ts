export type HealthStatus = {
  status: 'ok';
  service: 'swarm-agent';
};

export const getHealthStatus = (): HealthStatus => ({
  status: 'ok',
  service: 'swarm-agent',
});
