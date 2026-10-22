import { fetchCoreService } from "./coreServices";

export interface DetectionFinding {
  finding_id: string;
  finding_type: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence_score: number;
  explanation_text: string;
  creation_timestamp: string;
  state: "open" | "superseded" | "dismissed" | "escalated";
  context_snapshot: {
    asset: {
      asset_id: string;
      hostname?: string;
      environment?: string;
      criticality?: string;
      role?: string;
    };
    supporting_event_count?: number;
  };
  // UI-friendly derived/optional fields
  confidence?: number; // percentage 0-100
  explanation?: string;
  asset?: {
    asset_id: string;
    hostname?: string;
    environment?: string;
    criticality?: string;
    role?: string;
  };
  supporting_event_count?: number;
};

export type FindingListResponse = {
  findings: DetectionFinding[];
};

// Detection service feeds the SIEM and detection views.
// Normalize server fields to UI-friendly names to avoid duplication in components.
export const fetchFindings = async (signal?: AbortSignal): Promise<DetectionFinding[]> => {
  const response = await fetchCoreService<FindingListResponse>("detection", "/findings?limit=100", signal);
  // map to include UI-friendly fields
  return response.findings.map((f) => ({
    ...f,
    confidence: typeof f.confidence_score === "number" ? Math.round(f.confidence_score * 100) : undefined,
    explanation: f.explanation_text,
    asset: f.context_snapshot?.asset,
    supporting_event_count: f.context_snapshot?.supporting_event_count ?? 0
  }));
};
