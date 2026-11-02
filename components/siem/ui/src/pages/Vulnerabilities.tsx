import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchVulnerabilities } from "../api/vulnerability";
import SectionHeader from "../components/SectionHeader";
import type { VulnerabilityRecord } from "../api/vulnerability";
import { formatUtcTimestamp, toTitleCase } from "../utils/formatters";

const Vulnerabilities = () => {
  const [records, setRecords] = useState<VulnerabilityRecord[]>([]);

  useEffect(() => {
    const controller = new AbortController();

    fetchVulnerabilities(controller.signal)
      .then((data) => setRecords(data))
      .catch(() => setRecords([]));

    return () => controller.abort();
  }, []);

  const highExposure = records
    .filter((item) => item.risk_score.level === "high" || item.risk_score.level === "critical")
    .slice(0, 4);

  return (
    <section className="page">
      <header className="page__header">
        <div>
          <h1>Vulnerabilities</h1>
          <p className="page__subtitle">
            Exposure awareness with exploitability foregrounded. CVE counts are secondary.
          </p>
        </div>
        <Link className="ghost-button" to="/vulnerabilities">
          Review risk acceptances
        </Link>
      </header>

      <div className="grid grid--two">
        <section className="card">
          <SectionHeader
            title="Exposure-first views"
            description="Exposure scoring and attack path analysis."
          />
          {highExposure.length > 0 ? (
            <ul className="list">
              {highExposure.map((record) => (
                <li key={record.vulnerability_id}>
                  <div>
                    <strong>{record.asset_id}</strong>
                    <p>
                      {toTitleCase(record.risk_score.level)} risk · Exposure {record.exposure_profile.exposure_state}
                    </p>
                  </div>
                  <span className="badge">{Math.round(record.risk_score.score)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">Exposure map placeholder.</p>
          )}
        </section>
        <section className="card">
          <SectionHeader
            title="Vulnerability lifecycle"
            description="Lifecycle states with evidence-driven transitions."
          />
          <p className="muted">Lifecycle board placeholder.</p>
        </section>
        <section className="card">
          <SectionHeader
            title="Risk acceptance"
            description="Documented decisions and expiry reminders."
          />
          <p className="muted">Risk acceptance workflow placeholder.</p>
        </section>
        <section className="card">
          <SectionHeader
            title="Remediation guidance"
            description="Prioritised guidance tied to assets."
          />
          {highExposure.length > 0 ? (
            <ul className="list">
              {highExposure.map((record) => (
                <li key={`${record.vulnerability_id}-remediation`}>
                  <div>
                    <strong>{record.remediation.preferred}</strong>
                    <p>{record.asset_id}</p>
                  </div>
                  <span className="badge">{formatUtcTimestamp(record.evidence.captured_at)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">Guidance list placeholder.</p>
          )}
        </section>
      </div>
    </section>
  );
};

export default Vulnerabilities;
