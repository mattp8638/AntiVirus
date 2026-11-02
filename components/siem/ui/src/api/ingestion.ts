import { fetchCoreService } from "./coreServices";

export type AssetInventoryOverviewResponse = {
  asset_id: string;
  tenant_id: string;
  hostname: string;
  os_name?: string | null;
  os_version?: string | null;
  hardware_model?: string | null;
  software_count: number;
  users_count: number;
  groups_count: number;
  last_seen_at?: string | null;
  updated_at: string;
};

export type InventorySnapshotResponse = {
  hardware?: {
    manufacturer?: string | null;
    model?: string | null;
    serial_number?: string | null;
    cpu_model?: string | null;
    cpu_cores?: number | null;
    memory_mb?: number | null;
    storage_gb?: number | null;
  } | null;
  os?: {
    os_name: string;
    os_version: string;
    kernel_version?: string | null;
    architecture?: string | null;
    install_date?: string | null;
  } | null;
  software?: {
    items: Array<{
      name: string;
      vendor?: string | null;
      version?: string | null;
      install_date?: string | null;
      source?: string | null;
    }>;
  } | null;
  users?: {
    users: Array<{
      username: string;
      display_name?: string | null;
      uid?: string | null;
      is_admin: boolean;
      last_login_at?: string | null;
    }>;
  } | null;
  groups?: {
    groups: Array<{
      name: string;
      gid?: string | null;
      members: string[];
    }>;
  } | null;
};

export type TelemetryMetricSummaryResponse = {
  name: string;
  unit: string;
  last_value: number;
  last_observed_at: string;
};

export const fetchAssetInventoryOverviews = async (
  signal?: AbortSignal
): Promise<AssetInventoryOverviewResponse[]> => {
  return fetchCoreService<AssetInventoryOverviewResponse[]>(
    "ingestion",
    "/inventory/assets/overview",
    signal
  );
};

export const fetchAssetInventoryOverview = async (
  assetId: string,
  signal?: AbortSignal
): Promise<AssetInventoryOverviewResponse> => {
  return fetchCoreService<AssetInventoryOverviewResponse>(
    "ingestion",
    `/inventory/assets/${assetId}/overview`,
    signal
  );
};

export const fetchInventorySnapshot = async (
  assetId: string,
  signal?: AbortSignal
): Promise<InventorySnapshotResponse> => {
  return fetchCoreService<InventorySnapshotResponse>(
    "ingestion",
    `/inventory/${assetId}`,
    signal
  );
};

export const fetchTelemetryMetrics = async (
  assetId: string,
  signal?: AbortSignal
): Promise<TelemetryMetricSummaryResponse[]> => {
  return fetchCoreService<TelemetryMetricSummaryResponse[]>(
    "ingestion",
    `/telemetry/${assetId}/metrics`,
    signal
  );
};
