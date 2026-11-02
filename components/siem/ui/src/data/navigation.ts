export type NavItem = {
  label: string;
  path: string;
  description: string;
  subnav?: NavItem[];
};

export const primaryNavigation: NavItem[] = [
  {
    label: "Overview",
    path: "/overview",
    description: "Single pane of truth"
  },
  {
    label: "Assets",
    path: "/assets",
    description: "Asset anchor and posture"
  },
  {
    label: "RMM",
    path: "/rmm",
    description: "Operational health and control"
  },
  {
    label: "SIEM",
    path: "/siem",
    description: "Investigation and memory",
    subnav: [
      {
        label: "Event search",
        path: "/siem/search",
        description: "Query events"
      },
      {
        label: "Timeline reconstruction",
        path: "/siem/timeline",
        description: "Narrative view"
      },
      {
        label: "Correlation views",
        path: "/siem/correlation",
        description: "Link signals"
      },
      {
        label: "Evidence export",
        path: "/siem/export",
        description: "Bundle logs and artefacts"
      }
    ]
  },
  {
    label: "Detection & EDR",
    path: "/detection-edr",
    description: "Judgement and defence"
  },
  {
    label: "Vulnerabilities",
    path: "/vulnerabilities",
    description: "Exposure awareness"
  },
  {
    label: "Patch Management",
    path: "/patch-management",
    description: "Controlled change"
  },
  {
    label: "Penetration Testing",
    path: "/penetration-testing",
    description: "Validation and humility"
  },
  {
    label: "PSA / Workflows",
    path: "/psa-workflows",
    description: "Human accountability"
  },
  {
    label: "Compliance & Audit",
    path: "/compliance-audit",
    description: "Proof and evidence"
  },
  {
    label: "Administration",
    path: "/administration",
    description: "Platform configuration"
  }
];
