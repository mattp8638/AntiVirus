import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchFrameworkMappings } from "../api/compliance";
import SectionHeader from "../components/SectionHeader";
import type { FrameworkMapping } from "../api/compliance";
import { formatUtcTimestamp } from "../utils/formatters";

const ComplianceAudit = () => {
  const [mappings, setMappings] = useState<FrameworkMapping[]>([]);

  useEffect(() => {
    const controller = new AbortController();

    fetchFrameworkMappings(controller.signal)
      .then((data) => setMappings(data))
      .catch(() => setMappings([]));

    return () => controller.abort();
  }, []);

  const frameworks = Array.from(new Set(mappings.map((mapping) => mapping.framework))).slice(0, 4);

  return (
    <section className="page">
      <header className="page__header">
        <div>
          <h1>Compliance &amp; Audit</h1>
          <p className="page__subtitle">
            Proof and evidence with drift visibility and audit-ready bundles.
          </p>
        </div>
        <Link className="ghost-button" to="/compliance-audit">
          Generate audit bundle
        </Link>
      </header>

      <div className="grid grid--two">
        <section className="card">
          <SectionHeader
            title="Framework posture"
            description="Framework readiness and exceptions."
          />
          {frameworks.length > 0 ? (
            <ul className="list">
              {frameworks.map((framework) => (
                <li key={framework}>
                  <div>
                    <strong>{framework}</strong>
                    <p>{mappings.filter((mapping) => mapping.framework === framework).length} mapped controls</p>
                  </div>
                  <span className="badge">Active</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">Framework posture placeholder.</p>
          )}
        </section>
        <section className="card">
          <SectionHeader
            title="Per-control evidence"
            description="Evidence per control with traceability."
          />
          {mappings.length > 0 ? (
            <ul className="list">
              {mappings.slice(0, 4).map((mapping) => (
                <li key={`${mapping.control_id}-${mapping.framework}`}>
                  <div>
                    <strong>{mapping.control_id}</strong>
                    <p>{mapping.mapped_control}</p>
                  </div>
                  <span className="badge">{formatUtcTimestamp(mapping.mapped_at)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">Control evidence placeholder.</p>
          )}
        </section>
        <section className="card">
          <SectionHeader
            title="Drift history"
            description="Time-series drift and exception timelines."
          />
          <p className="muted">Drift history placeholder.</p>
        </section>
        <section className="card">
          <SectionHeader
            title="Audit bundle generation"
            description="Automated, curated audit bundles."
          />
          <p className="muted">Audit bundle placeholder.</p>
        </section>
      </div>
    </section>
  );
};

export default ComplianceAudit;
