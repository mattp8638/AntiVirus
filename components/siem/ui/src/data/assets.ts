export type Asset = {
  id: string;
  name: string;
  role: string;
  criticality: "Low" | "Medium" | "High" | "Critical";
  riskScore: number;
  lastSeen: string;
  owner: string;
};

// Remove template assets; UI should fetch real assets from the backend.
export const assets: Asset[] = [];

export const assetDetails: Record<string, unknown> = {};
