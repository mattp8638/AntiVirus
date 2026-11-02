import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { fetchTelemetryNodes } from "../api/rmm";
import DataTable from "../components/DataTable";
import MetricCard from "../components/MetricCard";
import SectionHeader from "../components/SectionHeader";
import {
  maintenanceWindows,
  rmmMetrics,
  scriptExecutions,
  telemetryNodes as fallbackNodes
} from "../data/rmm";
import type { TelemetryNode } from "../data/rmm";

const statusFilters = ["All", "Healthy", "Degraded", "At Risk"] as const;
type StatusFilter = (typeof statusFilters)[number];

const Rmm = () => (
  <RmmWorkspace />
);

const RmmWorkspace = () => {
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("All");
  const [nodes, setNodes] = useState<TelemetryNode[]>(fallbackNodes);

  useEffect(() => {
    const controller = new AbortController();

    fetchTelemetryNodes(controller.signal)
      .then((data) => {
        if (data.length > 0) {
          setNodes(data);
        }
      })
      .catch(() => {
        setNodes(fallbackNodes);
      });

    return () => controller.abort();
  }, []);

  const filteredNodes = useMemo(() => {
    const lowerQuery = query.trim().toLowerCase();
    return nodes.filter((node) => {
      const matchesQuery =
        !lowerQuery ||
        node.name.toLowerCase().includes(lowerQuery) ||
        node.assetId.toLowerCase().includes(lowerQuery);
      const matchesStatus = statusFilter === "All" || node.status === statusFilter;
      return matchesQuery && matchesStatus;
    });
  }, [nodes, query, statusFilter]);

  return (
    <section className="page">
      <header className="page__header">
        <div>
          <h1>RMM</h1>
          <p className="page__subtitle">
            Operational health and control with telemetry-first context. Security alerts live elsewhere.
          </p>
        </div>
        <Link className="ghost-button" to="/patch-management">
          View maintenance windows
        </Link>
      </header>

      <div className="grid grid--metrics">
        <MetricCard
          title="Fleet availability"
          value={`${rmmMetrics.availability}%`}
          subtitle="Rolling 30-day uptime"
          accent="success"
        />
        <MetricCard
          title="Assets at risk"
          value={rmmMetrics.assetsAtRisk}
          subtitle="Assets requiring intervention"
          accent="warning"
        />
        <MetricCard
          title="Maintenance windows"
          value={rmmMetrics.maintenanceWindows}
          subtitle="Scheduled in next 7 days"
        />
        <MetricCard
          title="Scripts needing review"
          value={rmmMetrics.scriptsNeedingReview}
          subtitle="Execution outcomes awaiting review"
          accent="risk"
        />
      </div>

      <section className="card">
        <SectionHeader
          title="Asset availability"
          description="Uptime and operational state linked back to asset records."
          actionLabel="View assets"
          actionPath="/assets"
        />
        <div className="filter-bar">
          <label className="filter-bar__item">
            <span className="eyebrow">Search assets</span>
            <input
              className="text-input"
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search by asset name or ID"
              aria-label="Search assets"
            />
          </label>
          <label className="filter-bar__item">
            <span className="eyebrow">Status filter</span>
            <select
              className="text-input"
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value as StatusFilter)}
            >
              {statusFilters.map((status) => (
                <option key={status} value={status}>
                  {status}
                </option>
              ))}
            </select>
          </label>
        </div>
        <DataTable
          caption="Live telemetry overview"
          columns={[
            {
              header: "Asset",
              accessor: (node) => (
                <Link className="text-link" to={`/assets/${node.assetId}`}>
                  {node.name}
                </Link>
              )
            },
            { header: "Asset ID", accessor: (node) => node.assetId },
            { header: "Uptime (days)", accessor: (node) => node.uptimeDays },
            { header: "Patch ring", accessor: (node) => node.patchRing },
            { header: "Availability", accessor: (node) => `${node.availability}%` },
            { header: "Status", accessor: (node) => node.status }
          ]}
          rows={filteredNodes}
        />
      </section>

      <div className="grid grid--two">
        <section className="card">
          <SectionHeader
            title="Maintenance windows"
            description="Change windows with ownership and clear blockers."
            actionLabel="Review patching"
            actionPath="/patch-management"
          />
          <ul className="list">
            {maintenanceWindows.map((window) => (
              <li key={window.id}>
                <div>
                  <strong>{window.scope}</strong>
                  <p>{window.window}</p>
                </div>
                <div className="list__meta">
                  <span>{window.owner}</span>
                  <span className="badge">{window.status}</span>
                </div>
              </li>
            ))}
          </ul>
        </section>

        <section className="card">
          <SectionHeader
            title="Script execution history"
            description="Approved scripts with traceable outcomes."
          />
          <ul className="list">
            {scriptExecutions.map((script) => (
              <li key={script.id}>
                <div>
                  <strong>{script.scriptName}</strong>
                  <p>{script.executedAt}</p>
                </div>
                <div className="list__meta">
                  <span>{script.executedBy}</span>
                  <span className="badge">{script.status}</span>
                </div>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </section>
  );
};

export default Rmm;
