import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchAgents, fetchRiskScores } from "../api/identity";
import SectionHeader from "../components/SectionHeader";

const Administration = () => {
  const [agentCount, setAgentCount] = useState<number | null>(null);
  const [riskScoreCount, setRiskScoreCount] = useState<number | null>(null);

  useEffect(() => {
    const controller = new AbortController();

    fetchAgents(controller.signal)
      .then((agents) => setAgentCount(agents.length))
      .catch(() => setAgentCount(null));

    fetchRiskScores(controller.signal)
      .then((scores) => setRiskScoreCount(scores.length))
      .catch(() => setRiskScoreCount(null));

    return () => controller.abort();
  }, []);

  return (
    <section className="page">
      <header className="page__header">
        <div>
          <h1>Administration</h1>
          <p className="page__subtitle">
            Platform configuration, identity, RBAC, and tenant controls.
          </p>
        </div>
        <Link className="ghost-button" to="/administration">
          Manage roles
        </Link>
      </header>

      <div className="grid grid--two">
        <section className="card">
          <SectionHeader
            title="Identity & RBAC"
            description="Roles, permissions, and audit trails."
          />
          <p className="muted">
            {agentCount !== null ? `${agentCount} identities active` : "RBAC configuration placeholder."}
          </p>
        </section>
        <section className="card">
          <SectionHeader
            title="Tenant configuration"
            description="Multi-tenant controls and isolation."
          />
          <p className="muted">Tenant settings placeholder.</p>
        </section>
        <section className="card">
          <SectionHeader
            title="System health controls"
            description="Read-only mode and safety switches."
          />
          <p className="muted">
            {riskScoreCount !== null ? `${riskScoreCount} risk profiles tracked` : "Platform safety controls placeholder."}
          </p>
        </section>
        <section className="card">
          <SectionHeader
            title="Integrations"
            description="Configured integrations with least privilege."
          />
          <p className="muted">Integration inventory placeholder.</p>
        </section>
      </div>
    </section>
  );
};

export default Administration;
