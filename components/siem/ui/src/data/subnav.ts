export type SubNavItem = {
  id: string
  label: string
  path: string
  icon?: string
  children?: SubNavItem[]
}

export const subnav: SubNavItem[] = [
  {
    id: "psa",
    label: "PSA",
    path: "/psa",
    children: [
      { id: "psa-cases", label: "Cases", path: "/psa/cases" },
      { id: "psa-tasks", label: "Tasks", path: "/psa/tasks" },
      { id: "psa-evidence", label: "Evidence", path: "/psa/evidence" },
      { id: "psa-slas", label: "SLA Policies", path: "/psa/slas" },
      { id: "psa-audit", label: "Audit Log", path: "/psa/audit" }
    ]
  },

  {
    id: "patch",
    label: "Patch",
    path: "/patch",
    children: [
      { id: "patch-catalog", label: "Catalog", path: "/patch/catalog" },
      { id: "patch-jobs", label: "Patch Jobs", path: "/patch/jobs" },
      { id: "patch-results", label: "Results", path: "/patch/results" }
    ]
  },

  {
    id: "penetration",
    label: "Penetration",
    path: "/penetration",
    children: [
      { id: "pentest-engagements", label: "Engagements", path: "/penetration/engagements" },
      { id: "pentest-findings", label: "Findings", path: "/penetration/findings" },
      { id: "pentest-evidence", label: "Evidence", path: "/penetration/evidence" }
    ]
  },

  {
    id: "rmm",
    label: "RMM",
    path: "/rmm",
    children: [
      { id: "rmm-profiles", label: "Profiles", path: "/rmm/profiles" },
      { id: "rmm-patches", label: "Patches", path: "/rmm/patches" },
      { id: "rmm-scripts", label: "Scripts", path: "/rmm/scripts" },
      { id: "rmm-jobs", label: "Jobs", path: "/rmm/jobs" }
    ]
  },

  {
    id: "siem",
    label: "SIEM",
    path: "/siem",
    children: [
      { id: "siem-ingest", label: "Ingestion", path: "/siem/ingest" },
      { id: "siem-events", label: "Events", path: "/siem/events" },
      { id: "siem-findings", label: "Findings", path: "/siem/findings" },
      { id: "siem-correlation", label: "Correlation", path: "/siem/correlation" }
    ]
  },

  {
    id: "edr",
    label: "EDR",
    path: "/edr",
    children: [
      { id: "edr-process", label: "Process Events", path: "/edr/process-events" },
      { id: "edr-file", label: "File Events", path: "/edr/file-events" },
      { id: "edr-detections", label: "Detections", path: "/edr/detections" }
    ]
  },

  {
    id: "vulnerability",
    label: "Vulnerability",
    path: "/vulnerability",
    children: [
      { id: "vuln-list", label: "Vulnerabilities", path: "/vulnerability/list" },
      { id: "vuln-assets", label: "Asset Observations", path: "/vulnerability/assets" },
      { id: "vuln-scans", label: "Scans", path: "/vulnerability/scans" }
    ]
  },

  {
    id: "auditing",
    label: "Auditing",
    path: "/auditing",
    children: [
      { id: "audit-frameworks", label: "Frameworks", path: "/auditing/frameworks" },
      { id: "audit-controls", label: "Controls", path: "/auditing/controls" },
      { id: "audit-assessments", label: "Assessments", path: "/auditing/assessments" },
      { id: "audit-gaps", label: "Gaps", path: "/auditing/gaps" }
    ]
  },

  {
    id: "identity",
    label: "Identity",
    path: "/identity",
    children: [
      { id: "identity-users", label: "Users", path: "/identity/users" },
      { id: "identity-orgs", label: "Organisations", path: "/identity/organisations" },
      { id: "identity-roles", label: "Roles", path: "/identity/roles" }
    ]
  },

  {
    id: "transport",
    label: "Transport",
    path: "/transport",
    children: [
      { id: "transport-agents", label: "Agents", path: "/transport/agents" },
      { id: "transport-messages", label: "Messages", path: "/transport/messages" }
    ]
  },

  {
    id: "ingestion",
    label: "Ingestion",
    path: "/ingestion",
    children: [
      { id: "ingestion-sources", label: "Sources", path: "/ingestion/sources" },
      { id: "ingestion-pipelines", label: "Pipelines", path: "/ingestion/pipelines" }
    ]
  }
]

export default subnav
