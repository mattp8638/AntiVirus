import { fetchCoreService } from "./coreServices";

export type PsaTicketRecord = {
  ticket_id: string;
  asset_id: string;
  priority: "p1" | "p2" | "p3" | "p4";
  status: "open" | "acknowledged" | "resolved" | "blocked";
  risk_score: number;
  sla_deadline: string;
  creation_timestamp: string;
  last_updated_at: string;
  system_recommendation?: string | null;
};

export type TicketListResponse = {
  tickets: PsaTicketRecord[];
};

export type TicketResponse = {
  status: string;
  ticket: PsaTicketRecord;
};

// PSA workflow service for ticketed actions and evidence linkage.
export const fetchTickets = async (signal?: AbortSignal): Promise<PsaTicketRecord[]> => {
  const response = await fetchCoreService<TicketListResponse>("psa", "/tickets", signal);
  return response.tickets ?? [];
};

export const fetchTicket = async (ticketId: string, signal?: AbortSignal): Promise<PsaTicketRecord> => {
  const response = await fetchCoreService<TicketResponse>("psa", `/tickets/${encodeURIComponent(ticketId)}`, signal);
  return response.ticket ?? (response as PsaTicketRecord);
};
