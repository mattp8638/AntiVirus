import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { fetchFindings } from "../api/detection";
import SectionHeader from "../components/SectionHeader";
import type { DetectionFinding } from "../api/detection";
import { formatUtcTimestamp, toTitleCase } from "../utils/formatters";

const severityRank: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};

const DetectionEdr = () => {
  const [findings, setFindings] = useState<DetectionFinding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const controller = new AbortController();

    fetchFindings(controller.signal)
      .then((data) => setFindings(data))
      .catch(() => setFindings([]))
      .finally(() => setLoading(false));

    return () => controller.abort();
  }, []);

  /**
   * Analyst-grade prioritisation:
   * - Open findings only
   * - Severity first
   * - Confidence second
   * - Most recent as tie-breaker
   */
  const prioritisedFindings = useMemo(() => {
    return [...findings]
      .filter((f) => f.state === "open")
      .sort((a, b) => {
        const sev =
          severityRank[b.severity] - severityRank[a.severity];
        if (sev !== 0) return sev;

        const conf = (b.confidence ?? 0) - (a.confidence ?? 0);
        if (conf !== 0) return conf;

        return (
          new Date(b.creation_timestamp).getTime() -
          new Date(a.creation_timestamp).getTime()
        );
      })
      .slice(0, 6);
  }, [findings]);

  return (
    <section className="page">
      <header className="page__header">
        <div>
          <h1>Detection &amp; EDR</h1>
          <p className="page__subtitle">
            Evidence-first judgement, local defence, and explainable outcomes.
          </p>
        </div>

        <Link
          className="ghost-button"
          to="/detection-edr?view=false-positives"
        >
          Review false positives
        </Link>
      </header>

      <div className="grid grid--two">
        {/* FINDINGS QUEUE */}
        <section className="card">
          <SectionHeader
            title="Active findings queue"
            description="Prioritised detections requiring analyst attention."
          />

          {loading ? (
            <p className="muted">Loading findings…</p>
          ) : prioritisedFindings.length > 0 ? (
            <ul className="list list--stacked">
              {prioritisedFindings.map((finding) => (
                <li
                  key={finding.finding_id}
                  className={`finding finding--${finding.severity}`}
                >
                  <div className="finding__header">
                    <div>
                      <strong>
                        {toTitleCase(finding.finding_type)}
                      </strong>
                      <p className="muted">
                        {finding.asset?.hostname ?? "Unknown asset"} ·{" "}
                        {finding.asset?.role ?? "unclassified"}
                      </p>
                    </div>

                    <div className="finding__meta">
                      <span
                        className={`badge badge--${finding.severity}`}
                      >
                        {toTitleCase(finding.severity)}
                      </span>
                      {typeof finding.confidence === "number" && (
                        <span className="confidence">
                          {finding.confidence}% confidence
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="finding__context">
                    <p className="finding__explanation">
                      {finding.explanation ??
                        "No explanation available for this finding."}
                    </p>
                    <small className="muted">
                      {finding.supporting_event_count ?? 0} supporting
                      events ·{" "}
                      {formatUtcTimestamp(
                        finding.creation_timestamp
                      )}
                    </small>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">
              No active findings requiring review.
            </p>
          )}
        </section>

        {/* DEFENCE ACTIONS */}
        <section className="card">
          <SectionHeader
            title="Defence actions"
            description="Endpoint containment actions enforced by policy."
          />
          <p className="muted">
            Recent process terminations, quarantines, and network
            isolations will appear here with full policy attribution.
          </p>
        </section>

        {/* FALSE POSITIVE REVIEW */}
        <section className="card">
          <SectionHeader
            title="False positive review"
            description="Dismissed or suppressed findings with recorded justification."
          />
          <p className="muted">
            Findings marked as false positives remain auditable and
            traceable to analyst decisions.
          </p>
        </section>

        {/* RULE ATTRIBUTION */}
        <section className="card">
          <SectionHeader
            title="Rule attribution"
            description="Detection logic mapped to explainability notes."
          />
          <p className="muted">
            Each finding is linked to the rule, heuristic, or behavioural
            policy that produced it, including trigger conditions.
          </p>
        </section>
      </div>
    </section>
  );
};

export default DetectionEdr;
