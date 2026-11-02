import { Link, useLocation } from "react-router-dom";

const labelMap: Record<string, string> = {
  overview: "Overview",
  assets: "Assets",
  rmm: "RMM",
  siem: "SIEM",
  "detection-edr": "Detection & EDR",
  vulnerabilities: "Vulnerabilities",
  "patch-management": "Patch Management",
  "penetration-testing": "Penetration Testing",
  "psa-workflows": "PSA / Workflows",
  "compliance-audit": "Compliance & Audit",
  administration: "Administration"
};

const Breadcrumbs = () => {
  const location = useLocation();
  const segments = location.pathname.split("/").filter(Boolean);

  return (
    <nav className="breadcrumbs" aria-label="Breadcrumb">
      <Link to="/overview">Home</Link>
      {segments.map((segment, index) => {
        const path = `/${segments.slice(0, index + 1).join("/")}`;
        const label = labelMap[segment] ?? segment;
        return (
          <span key={path}>
            <span className="breadcrumbs__separator">/</span>
            <Link to={path}>{label}</Link>
          </span>
        );
      })}
    </nav>
  );
};

export default Breadcrumbs;
