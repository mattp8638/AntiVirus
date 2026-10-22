import { fetchCoreService } from "./coreServices";

export type AgentResponse = {
  identity_id: string;
  hostname: string;
  os: string;
  last_seen_at: string;
  trust_state: string;
};

export type AgentPresenceResponse = {
  identity_id: string;
  hostname: string;
  os: string;
  trust_state: string;
  last_seen_at: string;
  status: string;
};

export type HeartbeatEventResponse = {
  event_id: string;
  agent_id: string;
  hostname: string;
  os: string;
  uptime_seconds: number;
  trust_state: string;
  received_at: string;
};

export type RiskScoreResponse = {
  identity_id: string;
  score: number;
  rationale: string;
};

// Identity endpoints provide the asset/agent inventory and telemetry signals.
export const fetchAgents = async (signal?: AbortSignal): Promise<AgentResponse[]> => {
  return fetchCoreService<AgentResponse[]>("identity", "/agents", signal);
};

export const fetchAgentPresence = async (signal?: AbortSignal): Promise<AgentPresenceResponse[]> => {
  return fetchCoreService<AgentPresenceResponse[]>("identity", "/agents/presence", signal);
};

export const fetchHeartbeats = async (signal?: AbortSignal): Promise<HeartbeatEventResponse[]> => {
  return fetchCoreService<HeartbeatEventResponse[]>("identity", "/heartbeats", signal);
};

export const fetchRiskScores = async (signal?: AbortSignal): Promise<RiskScoreResponse[]> => {
  return fetchCoreService<RiskScoreResponse[]>("identity", "/risk-scores", signal);
};
