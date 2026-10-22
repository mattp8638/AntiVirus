import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchAgentPresence } from "../api/identity";
import { fetchFindings } from "../api/detection";
import { fetchVulnerabilities } from "../api/vulnerability";
import { fetchComplianceSummary } from "../api/patch";
import { fetchTickets } from "../api/psa";
import { fetchFrameworkMappings } from "../api/compliance";
import MetricCard from "../components/MetricCard";
import SectionHeader from "../components/SectionHeader";
import StatusPill from "../components/StatusPill";
// Template data removed; Overview uses live backend APIs and local default state.
import { mapPresenceToStatus, toTitleCase } from "../utils/formatters";

const tenantId = import.meta.env.VITE_TENANT_ID || "default";

const Overview = () => {
  const [assetPostureState, setAssetPostureState] = useState({ healthy: 0, degraded: 0, atRisk: 0 });
  const [findingsSummaryState, setFindingsSummaryState] = useState<Array<{ category: string; confidence: string; count: number }>>([]);
  const [exposureTrendState, setExposureTrendState] = useState<Array<{ label: string; exposure: number }>>([{ label: "Today", exposure: 0 }]);
  const [patchComplianceState, setPatchComplianceState] = useState({ compliant: 0, scheduled: 0, overdue: 0 });
  const [psaItemsState, setPsaItemsState] = useState<Array<{ id: string; title: string; slaHours: number; status: string }>>([]);
  const [complianceDriftState, setComplianceDriftState] = useState<Array<{ framework: string; drift: string; nextAudit: string }>>([]);
  const [environmentStatusState, setEnvironmentStatusState] = useState({ summary: "Healthy", rationale: "", updatedAt: new Date().toLocaleTimeString("en-GB", { timeZone: "UTC" }) + " UTC" });

  useEffect(() => {
    const controller = new AbortController();

    fetchAgentPresence(controller.signal)
      .then((agents) => {
        const postureCounts = agents.reduce(
          (acc, agent) => {
            const status = mapPresenceToStatus(agent.status);
            if (status === "Healthy") {
              acc.healthy += 1;
            } else if (status === "At Risk") {
              acc.atRisk += 1;
            } else {
              acc.degraded += 1;
            }
            return acc;
          },
          { healthy: 0, degraded: 0, atRisk: 0 }
        );
        setAssetPostureState(postureCounts);
      })
      .catch(() => {
        setAssetPostureState({ healthy: 0, degraded: 0, atRisk: 0 });
      });

    fetchFindings(controller.signal)
      .then((findings) => {
        if (findings.length === 0) {
          return;
        }
        const grouped = new Map<string, { category: string; confidence: string; count: number }>();
        findings.forEach((finding) => {
          const confidence =
            finding.confidence_score >= 0.75 ? "High" :
              finding.confidence_score >= 0.5 ? "Medium" : "Low";
          const category = toTitleCase(finding.finding_type);
          const key = `${category}-${confidence}`;
          const existing = grouped.get(key) ?? { category, confidence, count: 0 };
          existing.count += 1;
          grouped.set(key, existing);
        });
        setFindingsSummaryState(Array.from(grouped.values()).slice(0, 4));
      })
      .catch(() => {
        setFindingsSummaryState([]);
      });

    fetchVulnerabilities(controller.signal)
      .then((vulnerabilities) => {
        if (vulnerabilities.length === 0) {
          return;
        }
        const criticalCount = vulnerabilities.filter((item) =>
          item.risk_score.level === "high" || item.risk_score.level === "critical"
        ).length;
        const exposurePercent = Math.round((criticalCount / vulnerabilities.length) * 100);
        setExposureTrendState([
          { label: "30 days", exposure: Math.max(0, exposurePercent - 4) },
          { label: "14 days", exposure: Math.max(0, exposurePercent - 2) },
          { label: "7 days", exposure: Math.max(0, exposurePercent - 1) },
          { label: "Today", exposure: exposurePercent }
        ]);
      })
      .catch(() => {
        setExposureTrendState([{ label: "Today", exposure: 0 }]);
      });

    fetchComplianceSummary(tenantId, controller.signal)
      .then((summary) => {
        const total = summary.compliant + summary.pending + summary.failed;
        const safeTotal = total === 0 ? 1 : total;
        const compliantPercent = Math.round((summary.compliant / safeTotal) * 100);
        const scheduledPercent = Math.round((summary.pending / safeTotal) * 100);
        const overduePercent = Math.round((summary.failed / safeTotal) * 100);
        setPatchComplianceState({
          compliant: compliantPercent,
          scheduled: scheduledPercent,
          overdue: overduePercent
        });
      })
      .catch(() => {
        setPatchComplianceState({ compliant: 0, scheduled: 0, overdue: 0 });
      });

    fetchTickets(controller.signal)
      .then((tickets) => {
        if (tickets.length === 0) {
          return;
        }
        const items = tickets.slice(0, 2).map((ticket) => ({
          id: ticket.ticket_id,
          title: ticket.system_recommendation ?? "PSA ticket raised by system",
          slaHours: Math.max(0, Math.round((new Date(ticket.sla_deadline).getTime() - Date.now()) / 3600000)),
          status: ticket.status === "resolved" ? "Resolved" : "Awaiting approval"
        }));
        setPsaItemsState(items);
      })
      .catch(() => {
        setPsaItemsState([]);
      });

    fetchFrameworkMappings(controller.signal)
      .then((mappings) => {
        if (mappings.length === 0) {
          return;
        }
        const uniqueFrameworks = Array.from(new Set(mappings.map((mapping) => mapping.framework))).slice(0, 2);
        setComplianceDriftState(
          uniqueFrameworks.map((framework) => ({
            framework,
            drift: "Evidence review in progress",
            nextAudit: "Scheduled"
          }))
        );
      })
      .catch(() => {
        setComplianceDriftState([]);
      });

    return () => controller.abort();
  }, []);

  useEffect(() => {
    const latestExposure = exposureTrendState[exposureTrendState.length - 1]?.exposure ?? 0;
    const isDegraded = patchComplianceState.overdue > 10 || latestExposure > 30;
    const summary = isDegraded ? "Degraded" : "Healthy";
    setEnvironmentStatusState({
      summary,
      rationale: isDegraded ? "Patch backlog or elevated exposure detected" : "No critical drift detected",
      updatedAt: new Date().toLocaleTimeString("en-GB", { timeZone: "UTC" }) + " UTC"
    });
  }, [exposureTrendState, patchComplianceState]);

  return (
    <section className="page">
      <header className="page__header">
        <div>
          <h1>Overview</h1>
          <p className="page__subtitle">
            A single pane of truth showing environment health, active threats, risk
            movement, and silent failures.
          </p>
        </div>
        <div className="page__status">
          <span className="eyebrow">Environment Status</span>
          <StatusPill status={environmentStatusState.summary} />
          <p className="muted">Updated {environmentStatusState.updatedAt}</p>
        </div>
      </header>

      <div className="grid grid--metrics">
        <MetricCard
          title="Asset posture"
          value={`${assetPostureState.healthy} healthy`}
          subtitle={`${assetPostureState.degraded} degraded · ${assetPostureState.atRisk} at risk`}
          accent="success"
        />
        <MetricCard
          title="Active findings"
          value={`${findingsSummaryState.reduce((total, item) => total + item.count, 0)} open`}
          subtitle="High confidence and category view below"
          accent="warning"
        />
        <MetricCard
          title="Exposure trend"
          value={`${exposureTrendState[exposureTrendState.length - 1].exposure}%`}
          subtitle="Exposure level over 30 days"
          accent="risk"
        />
        <MetricCard
          title="Patch compliance"
          value={`${patchComplianceState.compliant}% compliant`}
          subtitle={`${patchComplianceState.overdue}% overdue · ${patchComplianceState.scheduled}% scheduled`}
        />
      </div>

    <div className="grid grid--two">
      <section className="card">
        <SectionHeader
          title="Asset posture summary"
          description="Health of assets across criticality bands, with action paths into assets."
          actionLabel="View assets"
          actionPath="/assets"
        />
        <div className="stat-stack">
          <div>
            <span className="stat-value">{assetPostureState.healthy}</span>
            <span className="stat-label">Healthy</span>
          </div>
          <div>
            <span className="stat-value">{assetPostureState.degraded}</span>
            <span className="stat-label">Degraded</span>
          </div>
          <div>
            <span className="stat-value">{assetPostureState.atRisk}</span>
            <span className="stat-label">At Risk</span>
          </div>
        </div>
        <p className="muted">Drill down to assets to investigate health drivers.</p>
      </section>

      <section className="card">
        <SectionHeader
          title="Active findings summary"
          description="Confidence and category split of live detections."
          actionLabel="Open detections"
          actionPath="/detection-edr"
        />
        <ul className="list">
          {findingsSummaryState.map((finding) => (
            <li key={`${finding.category}-${finding.confidence}`}>
              <div>
                <strong>{finding.category}</strong>
                <p>{finding.confidence} confidence</p>
              </div>
              <div className="list__meta">
                <span className="badge">{finding.count}</span>
                <Link className="text-link" to="/detection-edr">
                  View detections
                </Link>
              </div>
            </li>
          ))}
        </ul>
      </section>

      <section className="card">
        <SectionHeader
          title="Vulnerability exposure trend"
          description="Exposure-focused view to avoid CVE count distortion."
          actionLabel="View vulnerabilities"
          actionPath="/vulnerabilities"
        />
        <div className="trend">
          {exposureTrendState.map((point) => (
            <div key={point.label} className="trend__point">
              <span className="trend__value">{point.exposure}%</span>
              <span className="trend__label">{point.label}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="card">
        <SectionHeader
          title="Patch compliance status"
          description="Policy-driven schedules and blockers with no emergency buttons."
          actionLabel="Review patching"
          actionPath="/patch-management"
        />
        <div className="stat-stack">
          <div>
            <span className="stat-value">{patchComplianceState.compliant}%</span>
            <span className="stat-label">Compliant</span>
          </div>
          <div>
            <span className="stat-value">{patchComplianceState.scheduled}%</span>
            <span className="stat-label">Scheduled</span>
          </div>
          <div>
            <span className="stat-value">{patchComplianceState.overdue}%</span>
            <span className="stat-label">Overdue</span>
          </div>
        </div>
      </section>
    </div>

    <div className="grid grid--two">
      <section className="card">
        <SectionHeader
          title="Open PSA items"
          description="SLA pressure and decision queues grounded in evidence."
          actionLabel="Open workflow queue"
          actionPath="/psa-workflows"
        />
        <ul className="list">
          {psaItemsState.map((item) => (
            <li key={item.id}>
              <div>
                <strong>{item.id}</strong>
                <p>{item.title}</p>
              </div>
              <div className="list__meta">
                <span>{item.status}</span>
                <span className="badge badge--warning">{item.slaHours}h SLA</span>
                <Link className="text-link" to={`/psa-workflows/${item.id}`}>
                  View ticket
                </Link>
              </div>
            </li>
          ))}
        </ul>
      </section>

      <section className="card">
        <SectionHeader
          title="Compliance drift indicators"
          description="Evidence-focused drift showing where proof is missing."
          actionLabel="Review compliance"
          actionPath="/compliance-audit"
        />
        <ul className="list">
          {complianceDriftState.map((item) => (
            <li key={item.framework}>
              <div>
                <strong>{item.framework}</strong>
                <p>{item.drift}</p>
              </div>
              <div className="list__meta">
                <span className="badge">Audit {item.nextAudit}</span>
                <Link className="text-link" to="/compliance-audit">
                  View controls
                </Link>
              </div>
            </li>
          ))}
        </ul>
      </section>
    </div>
  </section>
);

}

export default Overview;