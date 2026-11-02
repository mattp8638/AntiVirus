import { fetchCoreService } from "./coreServices";

export type PenTestApiResponse = {
  tests: Array<{
    test_id: string;
    tenant_id: string;
    test_type: string;
    method: string;
    status: string;
    created_at: string;
  }>;
};

export const fetchPenTests = async (signal?: AbortSignal): Promise<PenTestApiResponse> => {
  return fetchCoreService<PenTestApiResponse>("penetration", "/tests", signal);
};

export type PenTestDetailResponse = {
  status: string;
  test: {
    test_id: string;
    tenant_id: string;
    test_type: string;
    method: string;
    status: string;
    created_at: string;
    scope?: {
      assets?: string[];
      networks?: string[];
    };
  };
};

export const fetchPenTest = async (
  testId: string,
  signal?: AbortSignal
): Promise<PenTestDetailResponse> => {
  return fetchCoreService<PenTestDetailResponse>("penetration", `/tests/${encodeURIComponent(testId)}`, signal);
};
