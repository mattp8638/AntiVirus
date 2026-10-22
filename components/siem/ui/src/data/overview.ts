export type StatusLevel = "Healthy" | "Degraded" | "At Risk";

// Minimal empty/default telemetry placeholders. Real data is fetched from backend APIs.
export const environmentStatus: { summary: StatusLevel; rationale: string; updatedAt: string } = {
  summary: "Healthy",
  rationale: "",
  updatedAt: new Date().toLocaleTimeString("en-GB", { timeZone: "UTC" }) + " UTC"
};

export const assetPosture = {
  healthy: 0,
  degraded: 0,
  atRisk: 0
};

export const findingsSummary: Array<{ category: string; confidence: string; count: number }> = [];

export const exposureTrend = [{ label: "Today", exposure: 0 }];

export const patchCompliance = {
  compliant: 0,
  scheduled: 0,
  overdue: 0
};

export const psaItems: Array<{ id: string; title: string; slaHours: number; status: string }> = [];

export const complianceDrift: Array<{ framework: string; drift: string; nextAudit: string }> = [];
