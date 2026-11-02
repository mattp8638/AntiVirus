import StatusPill from "./StatusPill";

const GlobalHeader = () => (
  <header className="global-header" aria-label="Global header">
    <div className="global-header__left">
      <div className="tenant-selector" aria-label="Tenant selector">
        <span className="eyebrow">Tenant</span>
        <strong>Home Primary</strong>
      </div>
      <div className="indicator">
        <span className="eyebrow">Environment Risk</span>
        <StatusPill status={"Healthy"} />
      </div>
      <div className="indicator">
        <span className="eyebrow">Active Incidents</span>
        <strong>8 open / 2 critical</strong>
      </div>
    </div>
    <div className="global-header__right">
      <div className="indicator">
        <span className="eyebrow">System Health</span>
        <strong>Platform healthy</strong>
      </div>
      <div className="user-meta">
        <span className="eyebrow">Signed in</span>
        <strong>Matt Palmer</strong>
      </div>
    </div>
  </header>
);

export default GlobalHeader;
