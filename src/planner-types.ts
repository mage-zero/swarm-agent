export type PlannerResourceSpec = {
  limits: {
    cpu_cores: number;
    memory_bytes: number;
  };
  reservations: {
    cpu_cores: number;
    memory_bytes: number;
  };
};

export type PlannerResources = {
  services: Record<string, PlannerResourceSpec>;
};

export type InspectionMetricValue = number | string | boolean | null;

export type PlannerInspectionService = {
  name: string;
  service: string;
  environment_id?: number;
  container_ids: string[];
  replicas: number;
  constraints?: string[];
  sampled_container_id?: string;
  docker?: {
    cpu_percent: number;
    memory_bytes: number;
    memory_limit_bytes: number;
    memory_percent: number;
    pids: number;
  };
  app?: Record<string, InspectionMetricValue>;
  warnings?: string[];
};

export type PlannerInspectionPayload = {
  generated_at: string;
  services: PlannerInspectionService[];
  window_minutes?: number;
  sample_count?: number;
};

export type PlannerTuningService = {
  name: string;
  service: string;
  environment_id?: number;
  signals: {
    memory_limit_ratio?: number;
    memory_reservation_ratio?: number;
    cpu_percent?: number;
  };
  notes?: string[];
};

export type PlannerTuningAdjustment = {
  limits?: {
    memory_bytes?: number;
  };
  reservations?: {
    memory_bytes?: number;
  };
  source?: string;
  notes?: string[];
};

export type PlannerConfigChange = {
  service: string;
  changes: Record<string, number | string>;
  notes?: string[];
  evidence?: Record<string, number | string>;
};

export type PlannerTuningPlacement = {
  name: string;
  service: string;
  environment_id?: number;
  node_id: string;
  reason: string;
};

export type PlannerTuningProfile = {
  id: string;
  status: 'base' | 'recommended' | 'incremental' | 'approved';
  strategy: string;
  resources: PlannerResources;
  adjustments: Record<string, PlannerTuningAdjustment>;
  placements: PlannerTuningPlacement[];
  created_at: string;
  updated_at: string;
  confidence?: number;
  deterministic_confidence?: number;
  ai_confidence?: number;
  sample_count?: number;
  stability_streak?: number;
  summary?: string;
  config_changes?: PlannerConfigChange[];
};

export type PlannerTuningPayload = {
  generated_at: string;
  services: PlannerTuningService[];
  base_profile: PlannerTuningProfile;
  recommended_profile?: PlannerTuningProfile;
  incremental_profile?: PlannerTuningProfile;
  approved_profiles: PlannerTuningProfile[];
  active_profile_id: string;
};

export type PlannerCapacitySummary = {
  cpu_cores: number;
  memory_bytes: number;
  node_count: number;
};

export type PlannerCapacityChangeSku = {
  sku: string;
  plan: string;
  count: number;
  vcpu: number;
  ram_gb: number;
  disk_gb?: number;
  disk_type?: string;
};

export type PlannerCapacityChangeNodeRemoval = {
  node_id: string;
  hostname?: string;
  reason: string;
};

export type PlannerCapacityChangeProfile = {
  id: string;
  status: 'base' | 'recommended' | 'approved';
  strategy: string;
  change: 'none' | 'increase' | 'decrease';
  created_at: string;
  updated_at: string;
  capacity: PlannerCapacitySummary;
  required?: {
    cpu_cores: number;
    memory_bytes: number;
  };
  target_capacity?: PlannerCapacitySummary;
  skus?: PlannerCapacityChangeSku[];
  remove_nodes?: PlannerCapacityChangeNodeRemoval[];
  notes?: string[];
  summary?: string;
  ready?: boolean;
};

export type PlannerCapacityChangePayload = {
  generated_at: string;
  base_profile: PlannerCapacityChangeProfile;
  recommended_profile?: PlannerCapacityChangeProfile;
  approved_profiles: PlannerCapacityChangeProfile[];
  active_profile_id: string;
};

export type CapacityNode = {
  id?: string;
  hostname?: string;
  role?: string;
  status?: string;
  availability?: string;
  labels?: Record<string, string>;
  address?: string;
  resources?: {
    cpu_cores: number;
    memory_bytes: number;
  };
  reservations?: {
    cpu_cores: number;
    memory_bytes: number;
  };
  free?: {
    cpu_cores: number;
    memory_bytes: number;
  };
  tasks?: {
    running: number;
    services: string[];
  };
};
