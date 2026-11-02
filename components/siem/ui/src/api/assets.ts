import type { Asset } from "../data/assets";
import { fetchAssetInventoryOverviews } from "./ingestion";
import { formatRelativeTime } from "../utils/formatters";

const resolveLastSeen = (lastSeenAt?: string | null, updatedAt?: string | null) =>
  lastSeenAt ?? updatedAt ?? null;

// Build asset records from ingestion inventory overviews.
export const fetchAssets = async (signal?: AbortSignal): Promise<Asset[]> => {
  const overviews = await fetchAssetInventoryOverviews(signal);

  return overviews.map((overview) => {
    const lastSeen = resolveLastSeen(overview.last_seen_at, overview.updated_at);
    return {
      id: overview.asset_id,
      name: overview.hostname || overview.asset_id,
      role: overview.os_name ? overview.os_name : "Managed Asset",
      criticality: "Low",
      riskScore: 0,
      lastSeen: lastSeen ? formatRelativeTime(lastSeen) : "Unavailable",
      owner: overview.tenant_id
    };
  });
};
