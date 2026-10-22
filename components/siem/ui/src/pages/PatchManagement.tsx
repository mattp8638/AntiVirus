import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { fetchComplianceSummary } from "../api/patch";
import DataTable from "../components/DataTable";
import MetricCard from "../components/MetricCard";
import SectionHeader from "../components/SectionHeader";
import { patchItems, patchMetrics as fallbackMetrics, patchSchedules } from "../data/patch";
import type { PatchMetrics } from "../data/patch";

const patchFilters = ["All", "Compliant", "Scheduled", "Overdue", "Failed"] as const;
type PatchFilter = (typeof patchFilters)[number];

const tenantId = import.meta.env.VITE_TENANT_ID || "default";

const PatchManagement = () => (
  <PatchWorkspace />
);

const PatchWorkspace = () => {
  const [filter, setFilter] = useState<PatchFilter>("All");
  const [query, setQuery] = useState("");
  const [metrics, setMetrics] = useState<PatchMetrics>(fallbackMetrics);

  useEffect(() => {
    const controller = new AbortController();

    fetchComplianceSummary(tenantId, controller.signal)
      .then((summary) => {
        const total = summary.compliant + summary.pending + summary.failed;
        const safeTotal = total === 0 ? 1 : total;
        setMetrics({
          compliant: Math.round((summary.compliant / safeTotal) * 100),
          scheduled: Math.round((summary.pending / safeTotal) * 100),
          overdue: Math.round((summary.failed / safeTotal) * 100),
          failures: summary.failed
        });
      })
      .catch(() => {
        setMetrics(fallbackMetrics);
      });

    return () => controller.abort();
  }, []);

  const filteredItems = useMemo(() => {
    const lowerQuery = query.trim().toLowerCase();
    return patchItems.filter((item) => {
      const matchesQuery =
        !lowerQuery ||
        item.asset.toLowerCase().includes(lowerQuery) ||
        item.id.toLowerCase().includes(lowerQuery);
      const matchesFilter = filter === "All" || item.status === filter;
      return matchesQuery && matchesFilter;
    });
  }, [filter, query]);

  return (
    <section className="page">
      <header className="page__header">
        <div>
          <h1>Patch Management</h1>
          <p className="page__subtitle">
            Controlled change with policy-driven scheduling and clear blockers.
          </p>
        </div>
        <Link className="ghost-button" to="/patch-management">
          View patch policy
        </Link>
      </header>

      <div className="grid grid--metrics">
        <MetricCard
          title="Compliant"
          value={`${metrics.compliant}%`}
          subtitle="Assets within policy"
          accent="success"
        />
        <MetricCard
          title="Scheduled"
          value={`${metrics.scheduled}%`}
          subtitle="Next 14 days"
        />
        <MetricCard
          title="Overdue"
          value={`${metrics.overdue}%`}
          subtitle="Needs attention"
          accent="warning"
        />
        <MetricCard
          title="Failures"
          value={metrics.failures}
          subtitle="Blocked or failed runs"
          accent="risk"
        />
      </div>

      <section className="card">
        <SectionHeader
          title="Patch compliance"
          description="Live compliance view with blockers highlighted."
        />
        <div className="filter-bar">
          <label className="filter-bar__item">
            <span className="eyebrow">Search assets</span>
            <input
              className="text-input"
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search by asset or patch ID"
              aria-label="Search patch assets"
            />
          </label>
          <label className="filter-bar__item">
            <span className="eyebrow">Status</span>
            <select
              className="text-input"
              value={filter}
              onChange={(event) => setFilter(event.target.value as PatchFilter)}
            >
              {patchFilters.map((status) => (
                <option key={status} value={status}>
                  {status}
                </option>
              ))}
            </select>
          </label>
        </div>
        <DataTable
          caption="Patch compliance by asset"
          columns={[
            {
              header: "Patch ID",
              accessor: (item) => (
                <Link className="text-link" to={`/patch-management/${item.id}`}>
                  {item.id}
                </Link>
              )
            },
            { header: "Asset", accessor: (item) => item.asset },
            { header: "Ring", accessor: (item) => item.ring },
            { header: "Status", accessor: (item) => item.status },
            { header: "Last Patch", accessor: (item) => item.lastPatch },
            { header: "Next Window", accessor: (item) => item.nextWindow },
            { header: "Blocker", accessor: (item) => item.blocker ?? "-" }
          ]}
          rows={filteredItems}
        />
      </section>

      <div className="grid grid--two">
        <section className="card">
          <SectionHeader
            title="Upcoming schedules"
            description="Windows with readiness and ownership."
          />
          <ul className="list">
            {patchSchedules.map((schedule) => (
              <li key={schedule.id}>
                <div>
                  <strong>{schedule.window}</strong>
                  <p>{schedule.scope}</p>
                </div>
                <div className="list__meta">
                  <span>{schedule.owner}</span>
                  <span className="badge">{schedule.readiness}</span>
                </div>
              </li>
            ))}
          </ul>
        </section>

        <section className="card">
          <SectionHeader
            title="Failures and blockers"
            description="Failure detail with evidence-ready context."
          />
          <ul className="list">
            {patchItems
              .filter((item) => item.status === "Failed" || item.status === "Overdue")
              .map((item) => (
                <li key={item.id}>
                  <div>
                    <strong>{item.asset}</strong>
                    <p>{item.blocker ?? "No blocker recorded"}</p>
                  </div>
                  <span className="badge badge--warning">{item.status}</span>
                </li>
              ))}
          </ul>
        </section>
      </div>
    </section>
  );
};

export default PatchManagement;
