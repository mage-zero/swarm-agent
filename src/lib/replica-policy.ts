export type AppHaReplicaPolicyInput = {
  ready_node_count: number;
  free_cpu_cores: number;
  free_memory_bytes: number;
  nginx_reserve_cpu_cores: number;
  nginx_reserve_memory_bytes: number;
  php_fpm_reserve_cpu_cores: number;
  php_fpm_reserve_memory_bytes: number;
  min_ready_nodes: number;
  max_replicas: number;
};

export type AppHaReplicaPolicyDecision = {
  replicas: number;
  reason: 'single_node' | 'insufficient_headroom' | 'ha_enabled';
  required_cpu_cores: number;
  required_memory_bytes: number;
  shortfall_cpu_cores: number;
  shortfall_memory_bytes: number;
};

export type FrontendRuntimePolicy = {
  replicas: number;
  max_replicas_per_node: number;
  update_order: 'start-first' | 'stop-first';
  restart_condition: 'any';
};

export type FrontendRuntimeSpec = {
  replicas: number;
  max_replicas_per_node: number;
  update_order: string;
  restart_condition: string;
};

const APP_HA_CPU_EPSILON = 0.01;

export function resolveAppHaReplicaPolicy(input: AppHaReplicaPolicyInput): AppHaReplicaPolicyDecision {
  const readyNodeCount = Math.max(0, Math.floor(Number(input.ready_node_count) || 0));
  const minReadyNodes = Math.max(1, Math.floor(Number(input.min_ready_nodes) || 1));
  const maxReplicas = Math.max(1, Math.floor(Number(input.max_replicas) || 1));
  if (readyNodeCount < minReadyNodes || maxReplicas <= 1) {
    return {
      replicas: 1,
      reason: 'single_node',
      required_cpu_cores: 0,
      required_memory_bytes: 0,
      shortfall_cpu_cores: 0,
      shortfall_memory_bytes: 0,
    };
  }

  const targetReplicas = Math.max(1, Math.min(maxReplicas, readyNodeCount));
  if (targetReplicas <= 1) {
    return {
      replicas: 1,
      reason: 'single_node',
      required_cpu_cores: 0,
      required_memory_bytes: 0,
      shortfall_cpu_cores: 0,
      shortfall_memory_bytes: 0,
    };
  }

  const extraReplicas = targetReplicas - 1;
  const nginxReserveCpu = Math.max(0, Number(input.nginx_reserve_cpu_cores) || 0);
  const phpFpmReserveCpu = Math.max(0, Number(input.php_fpm_reserve_cpu_cores) || 0);
  const nginxReserveMem = Math.max(0, Math.round(Number(input.nginx_reserve_memory_bytes) || 0));
  const phpFpmReserveMem = Math.max(0, Math.round(Number(input.php_fpm_reserve_memory_bytes) || 0));
  const requiredCpu = extraReplicas * (nginxReserveCpu + phpFpmReserveCpu);
  const requiredMem = extraReplicas * (nginxReserveMem + phpFpmReserveMem);
  const freeCpu = Math.max(0, Number(input.free_cpu_cores) || 0);
  const freeMem = Math.max(0, Math.round(Number(input.free_memory_bytes) || 0));
  const shortfallCpu = requiredCpu > (freeCpu + APP_HA_CPU_EPSILON)
    ? Number((requiredCpu - freeCpu).toFixed(2))
    : 0;
  const shortfallMem = requiredMem > freeMem ? requiredMem - freeMem : 0;

  if (shortfallCpu > 0 || shortfallMem > 0) {
    return {
      replicas: 1,
      reason: 'insufficient_headroom',
      required_cpu_cores: Number(requiredCpu.toFixed(2)),
      required_memory_bytes: requiredMem,
      shortfall_cpu_cores: shortfallCpu,
      shortfall_memory_bytes: shortfallMem,
    };
  }

  return {
    replicas: targetReplicas,
    reason: 'ha_enabled',
    required_cpu_cores: Number(requiredCpu.toFixed(2)),
    required_memory_bytes: requiredMem,
    shortfall_cpu_cores: 0,
    shortfall_memory_bytes: 0,
  };
}

export function resolveFrontendRuntimePolicy(targetReplicas: number): FrontendRuntimePolicy {
  const replicas = Math.max(1, Math.round(Number(targetReplicas) || 1));
  return {
    replicas,
    // Keep single replica unconstrained so start-first can overlap briefly.
    max_replicas_per_node: replicas > 1 ? 1 : 0,
    // With one-per-node spread, start-first can deadlock when all nodes are occupied.
    update_order: replicas > 1 ? 'stop-first' : 'start-first',
    restart_condition: 'any',
  };
}
