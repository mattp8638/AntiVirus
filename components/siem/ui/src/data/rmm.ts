export type TelemetryStatus = "Healthy" | "Degraded" | "At Risk";

export type TelemetryNode = {
  assetId: string;
  name: string;
  uptimeDays: number;
  patchRing: string;
  availability: number;
  status: TelemetryStatus;
};

export type MaintenanceWindow = {
  id: string;
  scope: string;
  window: string;
  owner: string;
  status: "Scheduled" | "In Progress" | "Completed" | "Blocked";
};

export type ScriptExecution = {
  id: string;
  scriptName: string;
  executedBy: string;
  status: "Succeeded" | "Failed" | "Needs Review";
  executedAt: string;
};

export const telemetryNodes: TelemetryNode[] = [];
export const maintenanceWindows: MaintenanceWindow[] = [];
export const scriptExecutions: ScriptExecution[] = [];

export const rmmMetrics = { availability: 0, assetsAtRisk: 0, maintenanceWindows: 0, scriptsNeedingReview: 0 };
