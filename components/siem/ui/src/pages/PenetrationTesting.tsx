import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import DataTable from "../components/DataTable";
import MetricCard from "../components/MetricCard";
import SectionHeader from "../components/SectionHeader";
import { fetchPenTests } from "../api/penetration";
import { penetrationMetrics, penTests } from "../data/penetration";

type PenTestRecord = typeof penTests[number];

const PenetrationTesting = () => <PenetrationWorkspace />;

const PenetrationWorkspace = () => {
  const [tests, setTests] = useState<PenTestRecord[]>(penTests);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    setIsLoading(true);

    fetchPenTests(controller.signal)
      .then((response) => {
        const mapped: PenTestRecord[] = response.tests.map((test) => ({
          id: test.test_id,
          tenant: test.tenant_id,
          name: test.test_type,
          testType: test.test_type,
          method: test.method,
          window: test.created_at,
          status: (test.status.charAt(0).toUpperCase() + test.status.slice(1)) as PenTestRecord["status"],
          scope: "Imported from core-services",
          evidenceCount: 0
        }));
        setTests(mapped);
        setError(null);
      })
      .catch((err: Error) => {
        setError(err.message);
      })
      .finally(() => setIsLoading(false));

    return () => controller.abort();
  }, []);

  const filteredTests = useMemo(() => {
    const lowerQuery = query.trim().toLowerCase();
    return tests.filter((test) =>
      !lowerQuery ||
      test.name.toLowerCase().includes(lowerQuery) ||
      test.id.toLowerCase().includes(lowerQuery) ||
      test.testType.toLowerCase().includes(lowerQuery)
    );
  }, [tests, query]);

  return (
    <section className="page">
      <header className="page__header">
        <div>
          <h1>Penetration Testing</h1>
          <p className="page__subtitle">
            Validation and humility focused on what failed to detect or stop.
          </p>
        </div>
        <Link className="ghost-button" to="/penetration-testing">
          Schedule test
        </Link>
      </header>

      <div className="grid grid--metrics">
        <MetricCard
          title="Scheduled"
          value={penetrationMetrics.scheduled}
          subtitle="Upcoming tests"
        />
        <MetricCard
          title="Running"
          value={penetrationMetrics.running}
          subtitle="Live exercises"
          accent="warning"
        />
        <MetricCard
          title="Blocked"
          value={penetrationMetrics.blocked}
          subtitle="Requires remediation"
          accent="risk"
        />
        <MetricCard
          title="Evidence bundles"
          value={penetrationMetrics.evidenceBundles}
          subtitle="Captured artefacts"
          accent="success"
        />
      </div>

      <section className="card">
        <SectionHeader
          title="Pen test schedule"
          description="Authorised tests with scope, method, and evidence readiness."
        />
        <div className="filter-bar">
          <label className="filter-bar__item">
            <span className="eyebrow">Search tests</span>
            <input
              className="text-input"
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search by test ID or type"
              aria-label="Search tests"
            />
          </label>
          <div className="filter-bar__item">
            <span className="eyebrow">Integration status</span>
            <span className="muted">
              {isLoading ? "Syncing core-services" : error ? "Using local snapshot" : "Live sync active"}
            </span>
          </div>
        </div>
        {error ? <p className="muted">{error}</p> : null}
        <DataTable
          caption="Penetration tests"
          columns={[
            {
              header: "Test ID",
              accessor: (test) => (
                <Link className="text-link" to={`/penetration-testing/${test.id}`}>
                  {test.id}
                </Link>
              )
            },
            { header: "Name", accessor: (test) => test.name },
            { header: "Type", accessor: (test) => test.testType },
            { header: "Method", accessor: (test) => test.method },
            { header: "Window", accessor: (test) => test.window },
            { header: "Status", accessor: (test) => test.status },
            { header: "Evidence", accessor: (test) => test.evidenceCount }
          ]}
          rows={filteredTests}
        />
      </section>

      <div className="grid grid--two">
        <section className="card">
          <SectionHeader
            title="Control effectiveness"
            description="Outcome notes and detection gaps tied to tests."
          />
          <ul className="list">
            <li>
              <div>
                <strong>Identity resilience exercise</strong>
                <p>Legacy auth surfaced across 2 identities.</p>
              </div>
              <span className="badge badge--warning">Needs action</span>
            </li>
            <li>
              <div>
                <strong>Endpoint response drill</strong>
                <p>Containment triggered in 4 minutes.</p>
              </div>
              <span className="badge">Within SLA</span>
            </li>
          </ul>
        </section>

        <section className="card">
          <SectionHeader
            title="Evidence bundles"
            description="Evidence ready for audit and remediation."
          />
          <ul className="list">
            <li>
              <div>
                <strong>EV-1881</strong>
                <p>Endpoint response drill evidence pack.</p>
              </div>
              <Link className="text-link" to="/siem">
                View in SIEM
              </Link>
            </li>
            <li>
              <div>
                <strong>EV-1875</strong>
                <p>Identity resilience exercise artefacts.</p>
              </div>
              <Link className="text-link" to="/compliance-audit">
                Send to audit bundle
              </Link>
            </li>
          </ul>
        </section>
      </div>
    </section>
  );
};

export default PenetrationTesting;
