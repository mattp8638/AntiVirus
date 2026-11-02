export type TicketStatus = "New" | "In Progress" | "Awaiting Approval" | "Blocked" | "Resolved";
export type TicketPriority = "Low" | "Medium" | "High" | "Critical";

export type Ticket = {
  id: string;
  title: string;
  owner: string;
  priority: TicketPriority;
  status: TicketStatus;
  slaHoursRemaining: number;
  createdAt: string;
  linkedAsset: string;
  evidenceBundle: string;
};

// Remove template PSA data; UI should fetch tickets from the backend.
export const psaTickets: Ticket[] = [];

export const psaMetrics = {
  openTickets: 0,
  awaitingApproval: 0,
  breachedSla: 0,
  meanTimeToResolveHours: 0
};

export const psaWorkload: Array<{ owner: string; active: number; overdue: number }> = [];
