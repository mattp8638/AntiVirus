import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { fetchTickets } from "../api/psa";
import DataTable from "../components/DataTable";
import MetricCard from "../components/MetricCard";
import SectionHeader from "../components/SectionHeader";
import type { Ticket } from "../data/psa";
import { psaMetrics as fallbackMetrics, psaTickets as fallbackTickets, psaWorkload } from "../data/psa";
import type { PsaTicketRecord } from "../api/psa";

const statusOptions = ["All", "New", "In Progress", "Awaiting Approval", "Blocked", "Resolved"] as const;
type StatusOption = (typeof statusOptions)[number];

const PsaWorkflows = () => (
  <PsaWorkspace />
);

const mapPriority = (priority: PsaTicketRecord["priority"]): Ticket["priority"] => {
  switch (priority) {
    case "p1":
      return "Critical";
    case "p2":
      return "High";
    case "p3":
      return "Medium";
    case "p4":
      return "Low";
    default:
      return "Low";
  }
};

const mapStatus = (status: PsaTicketRecord["status"]): Ticket["status"] => {
  switch (status) {
    case "open":
      return "In Progress";
    case "acknowledged":
      return "Awaiting Approval";
    case "blocked":
      return "Blocked";
    case "resolved":
      return "Resolved";
    default:
      return "New";
  }
};

const hoursRemaining = (deadline: string) => {
  const deadlineDate = new Date(deadline);
  if (Number.isNaN(deadlineDate.getTime())) {
    return 0;
  }
  const diffMs = deadlineDate.getTime() - Date.now();
  return Math.max(0, Math.round(diffMs / 3600000));
};

const PsaWorkspace = () => {
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusOption>("All");
  const [tickets, setTickets] = useState<Ticket[]>(fallbackTickets);
  const [metrics, setMetrics] = useState(fallbackMetrics);
  const [workload, setWorkload] = useState(psaWorkload);

  useEffect(() => {
    const controller = new AbortController();

    fetchTickets(controller.signal)
      .then((data) => {
        if (data.length === 0) {
          return;
        }
        const mappedTickets = data.map<Ticket>((ticket) => ({
          id: ticket.ticket_id,
          title: ticket.system_recommendation ?? "System-generated PSA ticket",
          owner: "Service Desk",
          priority: mapPriority(ticket.priority),
          status: mapStatus(ticket.status),
          slaHoursRemaining: hoursRemaining(ticket.sla_deadline),
          createdAt: ticket.creation_timestamp,
          linkedAsset: ticket.asset_id,
          evidenceBundle: ticket.ticket_id
        }));
        setTickets(mappedTickets);

        const openTickets = mappedTickets.filter((ticket) => ticket.status !== "Resolved").length;
        const awaitingApproval = mappedTickets.filter(
          (ticket) => ticket.status === "Awaiting Approval"
        ).length;
        const breachedSla = mappedTickets.filter((ticket) => ticket.slaHoursRemaining === 0).length;
        const meanTimeToResolveHours = mappedTickets.length
          ? Math.round(
            mappedTickets.reduce((sum, ticket) => sum + ticket.slaHoursRemaining, 0) / mappedTickets.length
          )
          : fallbackMetrics.meanTimeToResolveHours;

        setMetrics({
          openTickets,
          awaitingApproval,
          breachedSla,
          meanTimeToResolveHours
        });

        const workloadMap = new Map<string, { owner: string; active: number; overdue: number }>();
        mappedTickets.forEach((ticket) => {
          const existing = workloadMap.get(ticket.owner) || { owner: ticket.owner, active: 0, overdue: 0 };
          existing.active += ticket.status === "Resolved" ? 0 : 1;
          existing.overdue += ticket.slaHoursRemaining === 0 ? 1 : 0;
          workloadMap.set(ticket.owner, existing);
        });
        setWorkload(Array.from(workloadMap.values()));
      })
      .catch(() => {
        setTickets(fallbackTickets);
        setMetrics(fallbackMetrics);
        setWorkload(psaWorkload);
      });

    return () => controller.abort();
  }, []);

  const filteredTickets = useMemo(() => {
    const lowerQuery = query.trim().toLowerCase();
    return tickets.filter((ticket) => {
      const matchesQuery =
        !lowerQuery ||
        ticket.title.toLowerCase().includes(lowerQuery) ||
        ticket.id.toLowerCase().includes(lowerQuery) ||
        ticket.owner.toLowerCase().includes(lowerQuery);
      const matchesStatus = statusFilter === "All" || ticket.status === statusFilter;
      return matchesQuery && matchesStatus;
    });
  }, [query, statusFilter, tickets]);

  return (
    <section className="page">
      <header className="page__header">
        <div>
          <h1>PSA / Workflows</h1>
          <p className="page__subtitle">
            Human accountability with evidence-backed ticketing and approvals.
          </p>
        </div>
        <Link className="ghost-button" to="/psa-workflows">
          View approval queue
        </Link>
      </header>

      <div className="grid grid--metrics">
        <MetricCard
          title="Open tickets"
          value={metrics.openTickets}
          subtitle="Active items requiring action"
          accent="warning"
        />
        <MetricCard
          title="Awaiting approval"
          value={metrics.awaitingApproval}
          subtitle="Decision queue"
        />
        <MetricCard
          title="SLA breaches"
          value={metrics.breachedSla}
          subtitle="Immediate escalation required"
          accent="risk"
        />
        <MetricCard
          title="MTTR"
          value={`${metrics.meanTimeToResolveHours}h`}
          subtitle="Mean time to resolve"
          accent="success"
        />
      </div>

      <section className="card">
        <SectionHeader
          title="Ticket queue"
          description="Tickets derived from system truth, filtered by SLA pressure."
        />
        <div className="filter-bar">
          <label className="filter-bar__item">
            <span className="eyebrow">Search tickets</span>
            <input
              className="text-input"
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search by ticket, title, or owner"
              aria-label="Search tickets"
            />
          </label>
          <label className="filter-bar__item">
            <span className="eyebrow">Status</span>
            <select
              className="text-input"
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value as StatusOption)}
            >
              {statusOptions.map((status) => (
                <option key={status} value={status}>
                  {status}
                </option>
              ))}
            </select>
          </label>
        </div>
        <DataTable
          caption="Evidence-backed tickets"
          columns={[
            {
              header: "Ticket",
              accessor: (ticket) => (
                <Link className="text-link" to={`/psa-workflows/${ticket.id}`}>
                  {ticket.id}
                </Link>
              )
            },
            { header: "Title", accessor: (ticket) => ticket.title },
            { header: "Owner", accessor: (ticket) => ticket.owner },
            { header: "Priority", accessor: (ticket) => ticket.priority },
            { header: "Status", accessor: (ticket) => ticket.status },
            {
              header: "SLA (hrs)",
              accessor: (ticket) => (
                <span className={ticket.slaHoursRemaining <= 4 ? "sla-risk" : ""}>
                  {ticket.slaHoursRemaining}
                </span>
              )
            },
            { header: "Evidence", accessor: (ticket) => ticket.evidenceBundle }
          ]}
          rows={filteredTickets}
        />
      </section>

      <div className="grid grid--two">
        <section className="card">
          <SectionHeader
            title="SLA pressure indicators"
            description="Teams under pressure, with escalation signals."
          />
          <ul className="list">
            {workload.map((team) => (
              <li key={team.owner}>
                <div>
                  <strong>{team.owner}</strong>
                  <p>{team.active} active tickets</p>
                </div>
                <span className={team.overdue > 0 ? "badge badge--warning" : "badge"}>
                  {team.overdue} overdue
                </span>
              </li>
            ))}
          </ul>
        </section>

        <section className="card">
          <SectionHeader
            title="Approval actions"
            description="Decisions attributable to named roles."
          />
          <ul className="list">
            {tickets
              .filter((ticket) => ticket.status === "Awaiting Approval")
              .map((ticket) => (
                <li key={ticket.id}>
                  <div>
                    <strong>{ticket.id}</strong>
                    <p>{ticket.title}</p>
                  </div>
                  <Link className="text-link" to={`/psa-workflows/${ticket.id}`}>
                    View ticket
                  </Link>
                </li>
              ))}
          </ul>
        </section>
      </div>
    </section>
  );
};

export default PsaWorkflows;
