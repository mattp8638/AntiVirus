import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { fetchTicket } from "../api/psa";
import SectionHeader from "../components/SectionHeader";
import type { Ticket } from "../data/psa";
import { psaTickets } from "../data/psa";
import type { PsaTicketRecord } from "../api/psa";

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

const PsaTicketDetail = () => {
  const { ticketId } = useParams();
  const fallbackTicket = psaTickets.find((item) => item.id === ticketId);
  const [ticket, setTicket] = useState<Ticket | undefined>(fallbackTicket);

  useEffect(() => {
    if (!ticketId) {
      return undefined;
    }
    const controller = new AbortController();

    fetchTicket(ticketId, controller.signal)
      .then((response) => {
        const mapped: Ticket = {
          id: response.ticket_id,
          title: response.system_recommendation ?? "System-generated PSA ticket",
          owner: "Service Desk",
          priority: mapPriority(response.priority),
          status: mapStatus(response.status),
          slaHoursRemaining: hoursRemaining(response.sla_deadline),
          createdAt: response.creation_timestamp,
          linkedAsset: response.asset_id,
          evidenceBundle: response.ticket_id
        };
        setTicket(mapped);
      })
      .catch(() => {
        setTicket(fallbackTicket);
      });

    return () => controller.abort();
  }, [fallbackTicket, ticketId]);

  if (!ticket) {
    return (
      <section className="page">
        <h1>Ticket not found</h1>
        <p className="page__subtitle">
          The selected PSA ticket is unavailable. Please return to the workflow queue.
        </p>
        <Link className="ghost-button" to="/psa-workflows">
          Back to PSA dashboard
        </Link>
      </section>
    );
  }

  return (
    <section className="page">
      <header className="page__header">
        <div>
          <h1>{ticket.id}</h1>
          <p className="page__subtitle">{ticket.title}</p>
        </div>
        <Link className="ghost-button" to={`/assets/${ticket.linkedAsset}`}>
          View linked asset
        </Link>
      </header>

      <div className="grid grid--two">
        <section className="card">
          <SectionHeader
            title="Ticket context"
            description="Owner, priority, and SLA pressure for accountable decisions."
          />
          <ul className="list list--compact">
            <li>
              <span>Owner</span>
              <strong>{ticket.owner}</strong>
            </li>
            <li>
              <span>Priority</span>
              <strong>{ticket.priority}</strong>
            </li>
            <li>
              <span>Status</span>
              <strong>{ticket.status}</strong>
            </li>
            <li>
              <span>SLA remaining</span>
              <strong>{ticket.slaHoursRemaining} hours</strong>
            </li>
          </ul>
        </section>

        <section className="card">
          <SectionHeader
            title="Evidence bundle"
            description="Evidence is immutable and must be reviewed before action."
          />
          <p>
            Bundle reference <strong>{ticket.evidenceBundle}</strong>
          </p>
          <Link className="ghost-button" to="/siem">
            Open evidence in SIEM
          </Link>
        </section>
      </div>

      <section className="card">
        <SectionHeader
          title="Decision log"
          description="Maintain attributable decisions and approvals."
        />
        <ul className="list">
          <li>
            <div>
              <strong>Created</strong>
              <p>{ticket.createdAt} UTC</p>
            </div>
            <span className="badge">System generated</span>
          </li>
          <li>
            <div>
              <strong>Current state</strong>
              <p>{ticket.status}</p>
            </div>
            <span className="badge">Awaiting action</span>
          </li>
        </ul>
      </section>
    </section>
  );
};

export default PsaTicketDetail;
