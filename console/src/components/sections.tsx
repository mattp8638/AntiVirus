import { Link, useLocation } from "react-router-dom";

// Related pages share one sidebar entry and switch between each other with these tabs. The pages keep their own
// addresses, so bookmarks, links from tickets and the routes of older versions keep working.

export interface SectionItem { to: string; label: string }

export const COMPLIANCE_SECTION: SectionItem[] = [
  { to: "/governance", label: "Programmes" },
  { to: "/continuous-compliance", label: "Continuous assurance" },
  { to: "/compliance", label: "Live posture" },
  { to: "/registers", label: "Registers & reviews" },
  { to: "/gaps", label: "Gaps" },
  { to: "/questionnaires", label: "Questionnaires" },
  { to: "/trust-centre", label: "Trust centre" },
  { to: "/ai-governance", label: "AI governance" },
  { to: "/agreements", label: "Agreements" },
  { to: "/continuity", label: "Business continuity" },
];
export const NETWORK_SECTION: SectionItem[] = [
  { to: "/network", label: "Service checks" },
  { to: "/network-topology", label: "Topology" },
];
export const M365_SECTION: SectionItem[] = [
  { to: "/m365", label: "Customer tenants" },
  { to: "/m365-partner", label: "Partner & standards" },
];

export function SectionTabs({ items }: { items: SectionItem[] }) {
  const { pathname } = useLocation();
  return (
    <nav className="section-tabs" aria-label="Section">
      {items.map((item) => {
        const active = pathname === item.to || pathname.startsWith(`${item.to}/`);
        return <Link key={item.to} to={item.to} className={active ? "active" : ""} aria-current={active ? "page" : undefined}>{item.label}</Link>;
      })}
    </nav>
  );
}
