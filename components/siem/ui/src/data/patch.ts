export type PatchStatus = "Compliant" | "Scheduled" | "Overdue" | "Failed";

export type PatchItem = {
  id: string;
  asset: string;
  ring: string;
  status: PatchStatus;
  lastPatch: string;
  nextWindow: string;
  blocker?: string;
};

export type PatchSchedule = {
  id: string;
  window: string;
  scope: string;
  owner: string;
  readiness: "Ready" | "Needs Approval" | "Blocked";
};

export type PatchMetrics = {
  compliant: number;
  scheduled: number;
  overdue: number;
  failures: number;
};

// Remove seeded template data; UI should display live patch telemetry from backend APIs.
export const patchItems: PatchItem[] = [];
export const patchSchedules: PatchSchedule[] = [];
export const patchMetrics: PatchMetrics = { compliant: 0, scheduled: 0, overdue: 0, failures: 0 };
