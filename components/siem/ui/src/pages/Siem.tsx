import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchFindings } from "../api/detection";
import SectionHeader from "../components/SectionHeader";
import type { DetectionFinding } from "../api/detection";
import { formatUtcTimestamp, toTitleCase } from "../utils/formatters";

const Siem = () => {
  const [findings, setFindings] = useState<DetectionFinding[]>([]);

  useEffect(() => {
    const controller = new AbortController();

    fetchFindings(controller.signal)
      .then((data) => setFindings(data))
      .catch(() => setFindings([]));

    return () => controller.abort();
  }, []);

  const recentFindings = findings.slice(0, 4);

  return (
    <section className="page">
      <header className="page__header">
        <div>
          <h1>SIEM</h1>
          <p className="page__subtitle">
            Investigation and memory focused on reconstruction, not reaction.
          </p>
        </div>
        <Link className="ghost-button" to="/siem">
          Export evidence
        </Link>
      </header>

      <div className="grid grid--two">
        <section className="card">
          <SectionHeader
            title="Event search"
            description="Query events with cancellation and provenance."
          />
          <p className="muted">
            {findings.length > 0
              ? `${findings.length} correlated findings ready for investigation.`
              : "Search bar and filters (placeholder)."}
          </p>
        </section>
        <section className="card">
          <SectionHeader
            title="Timeline reconstruction"
            description="Narrative view of incident chains."
          />
          {recentFindings.length > 0 ? (
            <ul className="list">
              {recentFindings.map((finding) => (
                <li key={finding.finding_id}>
                  <div>
                    <strong>{toTitleCase(finding.finding_type)}</strong>
                    <p>{finding.context_snapshot.asset.asset_id}</p>
                  </div>
                  <span className="badge">{formatUtcTimestamp(finding.creation_timestamp)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">Timeline workspace with evidence links.</p>
          )}
        </section>
        <section className="card">
          <SectionHeader
            title="Correlation views"
            description="Link signals without severity inflation."
          />
          <p className="muted">Correlation graph placeholder.</p>
        </section>
        <section className="card">
          <SectionHeader
            title="Evidence export"
            description="Bundle logs, artefacts, and commentary."
          />
          <p className="muted">Export queue and audit trail.</p>
        </section>
      </div>
    </section>
  );
};

export default Siem;
