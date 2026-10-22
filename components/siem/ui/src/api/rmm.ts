import type { TelemetryNode } from "../data/rmm";
import { fetchAgentPresence, fetchHeartbeats } from "./identity";
import { mapPresenceToStatus } from "../utils/formatters";

// Combine identity presence and heartbeat telemetry into RMM node summaries.
export const fetchTelemetryNodes = async (signal?: AbortSignal): Promise<TelemetryNode[]> => {
  const [presence, heartbeats] = await Promise.all([
    fetchAgentPresence(signal),
    fetchHeartbeats(signal)
  ]);

  const heartbeatMap = new Map(heartbeats.map((event) => [event.agent_id, event]));

  return presence.map((agent) => {
    const heartbeat = heartbeatMap.get(agent.identity_id);
    const uptimeSeconds = heartbeat?.uptime_seconds ?? 0;
    const uptimeDays = Math.max(0, Math.round(uptimeSeconds / 86400));
    const availability = uptimeDays > 180 ? 99.9 : uptimeDays > 30 ? 99.2 : 98.0;

    return {
      assetId: agent.identity_id,
      name: agent.hostname || agent.identity_id,
      uptimeDays,
      patchRing: "Ring 1",
      availability,
      status: mapPresenceToStatus(agent.status)
    };
  });
};
