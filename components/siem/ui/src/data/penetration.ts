export type PenTestStatus = "Planned" | "Running" | "Completed" | "Blocked" | "Aborted";

export type PenTest = {
  id: string;
  tenant: string;
  name: string;
  testType: string;
  method: string;
  window: string;
  status: PenTestStatus;
  scope: string;
  evidenceCount: number;
};

export const penTests: PenTest[] = [];

export const penetrationMetrics = { scheduled: 0, running: 0, blocked: 0, evidenceBundles: 0 };
