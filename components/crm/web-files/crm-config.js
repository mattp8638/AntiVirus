/* Palmertech CRM/ERP Centralized Configuration & Persistent Database Engine */

// Default Seed Data
const DEFAULT_CRM_DATABASE = {
  branding: {
    name: "Palmertech CRM",
    shortName: "PT",
    logoGradients: "linear-gradient(135deg, var(--accent-blue), var(--accent-green))",
    accentColor: "#3b82f6",
    accentGlow: "rgba(59, 130, 246, 0.4)"
  },
  user: {
    name: "Matt Admin",
    role: "Super Administrator",
    initials: "MA"
  },
  navigation: [
    { label: "Dashboard", url: "/dashboard/", icon: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>` },
    { label: "Leads (CRM)", url: "/leads/", icon: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>` },
    { label: "Projects (ERP)", url: "/projects/", icon: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path></svg>` },
    { label: "Invoices", url: "/invoices/", icon: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"></rect><line x1="1" y1="10" x2="23" y2="10"></line></svg>` },
    { label: "Helpdesk (Support)", url: "/support/", icon: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>` },
    { label: "Settings", url: "/settings/", icon: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>` }
  ],
  leads: [
    { company: "Aurora & Oak", contact: "Sarah Connor", email: "sarah@auroraandoak.co.uk", value: 3500, stage: "Qualified", date: "30 Jun 2026" },
    { company: "Errant Arts", contact: "John Miller", email: "john@errant-arts.co.uk", value: 2499, stage: "Contacted", date: "28 Jun 2026" },
    { company: "RLW Writing", contact: "Rose Watson", email: "rose@rlwwriting.co.uk", value: 1200, stage: "New", date: "29 Jun 2026" },
    { company: "Cyberdyne Systems Corp", contact: "Miles Dyson", email: "dyson@cyberdyne.com", value: 9500, stage: "Lost", date: "15 Jun 2026" }
  ],
  projects: [
    { 
      name: "Aurora & Oak", 
      details: "E-Commerce / Custom template", 
      targetDate: "15 Aug 2026", 
      progress: 80, 
      status: "Active", 
      phase: "Phase 3: Integration",
      tasks: [
        { id: "ao-1", name: "Configure database models", status: "Done" },
        { id: "ao-2", name: "Setup checkout API endpoints", status: "Done" },
        { id: "ao-3", name: "Perform visual layout styling", status: "Done" },
        { id: "ao-4", name: "Shipping service test run", status: "Done" },
        { id: "ao-5", name: "Verify client stripe webhooks", status: "ToDo" }
      ]
    },
    { 
      name: "Errant Arts", 
      details: "Design Agency Showcase", 
      targetDate: "01 Oct 2026", 
      progress: 45, 
      status: "Active", 
      phase: "Phase 2: User Testing",
      tasks: [
        { id: "ea-1", name: "Finalise wireframes", status: "Done" },
        { id: "ea-2", name: "Implement custom grid system", status: "InProgress" },
        { id: "ea-3", name: "User profile backend coding", status: "ToDo" },
        { id: "ea-4", name: "Testing layout animations", status: "ToDo" }
      ]
    },
    { 
      name: "RLW Writing", 
      details: "Bespoke Author Portal", 
      targetDate: "20 Jul 2026", 
      progress: 100, 
      status: "Completed", 
      phase: "Launch Ready",
      tasks: [
        { id: "rw-1", name: "Setup project outline", status: "Done" },
        { id: "rw-2", name: "Publishing workflow rules", status: "Done" },
        { id: "rw-3", name: "Conduct final deployment review", status: "Done" }
      ]
    },
    { 
      name: "MJR Palmer", 
      details: "Custom Database Portal", 
      targetDate: "15 Nov 2026", 
      progress: 15, 
      status: "Warning", 
      phase: "Phase 1: Wireframing",
      tasks: [
        { id: "mp-1", name: "Review data schema requirements", status: "Done" },
        { id: "mp-2", name: "Design grid prototype styles", status: "ToDo" },
        { id: "mp-3", name: "Build custom database views", status: "ToDo" },
        { id: "mp-4", name: "Setup basic authentication rules", status: "ToDo" }
      ]
    }
  ],
  invoices: [
    { id: "#INV-2026-004", client: "RLW Writing", details: "Bespoke Platform", amount: 2499, dueDate: "25 Jun 2026", status: "Paid", paymentDate: "26 Jun 2026" },
    { id: "#INV-2026-003", client: "Aurora & Oak", details: "E-Commerce Core", amount: 3500, dueDate: "10 Jul 2026", status: "Unpaid", paymentDate: "-" },
    { id: "#INV-2026-002", client: "Errant Arts", details: "Corporate Showcase", amount: 2499, dueDate: "15 Jun 2026", status: "Overdue", paymentDate: "-" },
    { id: "#INV-2026-001", client: "MJR Palmer", details: "Database integration", amount: 1500, dueDate: "05 Jun 2026", status: "Overdue", paymentDate: "-" }
  ],
  tickets: [
    {
      id: 1,
      ticketCode: "TKT-009",
      title: "Database view styling issue",
      account: "MJR Palmer",
      priority: "Critical",
      status: "Active Chat",
      updatedText: "Updated 10m ago",
      messages: [
        { sender: "client", initials: "MP", name: "Client", time: "10:15 AM", text: "Hey, some of the styling inside our grids doesn't look correct. The header is displaying gray and there are white blocks breaking the dark theme context." },
        { sender: "agent", initials: "MA", name: "Agent (Matt)", time: "10:22 AM", text: "Hello MJR Palmer team, we've identified that the system portal basic theme was overriding styles. We've updated the overrides in theme.css with !important rules to ensure the dark theme is forced globally. Please clear cache and verify." },
        { sender: "client", initials: "MP", name: "Client", time: "10:28 AM", text: "Excellent, that completely solved it! Thank you for the quick turn-around." }
      ]
    },
    {
      id: 2,
      ticketCode: "TKT-008",
      title: "Stripe integration checkout",
      account: "Aurora & Oak",
      priority: "Medium",
      status: "Awaiting Agent",
      updatedText: "Updated 2h ago",
      messages: [
        { sender: "client", initials: "AO", name: "Client", time: "08:30 AM", text: "We are getting a webhook verification error when processing production payments. Can you check our environment secrets?" }
      ]
    },
    {
      id: 3,
      ticketCode: "TKT-007",
      title: "Update text header copy",
      account: "RLW Writing",
      priority: "Low",
      status: "Awaiting Agent",
      updatedText: "Updated 1d ago",
      messages: [
        { sender: "client", initials: "RW", name: "Client", time: "Yesterday", text: "Could you change the landing hero subtitle to 'Professional Editing & Ghostwriting Services'?" }
      ]
    }
  ],
  timeline: [
    { type: "success", title: "New Lead Registered: Aurora & Oak", text: "Inquiry received via website contact form. Routing to sales pipeline.", time: "10 mins ago" },
    { type: "info", title: "Milestone Completed: Errant Arts", text: "Phase 2 UX/UI prototype layouts designed and approved by client.", time: "2 hours ago" },
    { type: "warning", title: "Invoice Paid: RLW Writing", text: "Invoice #INV-2026-004 ($2,499) marked as PAID via stripe checkout.", time: "Yesterday" },
    { type: "danger", title: "High Priority Support Ticket", text: "Client MJR Palmer reported styling issues on database views.", time: "Yesterday" }
  ]
};

// Initialize configuration object
window.CRM_CONFIG = {};

// Load Database State from localStorage or write default seeds
const savedDb = localStorage.getItem("CRM_DATABASE_STATE");
if (savedDb) {
  try {
    window.CRM_CONFIG = JSON.parse(savedDb);
  } catch (err) {
    console.error("Error reading persistent CRM database state:", err);
    window.CRM_CONFIG = JSON.parse(JSON.stringify(DEFAULT_CRM_DATABASE));
  }
} else {
  // Save initial defaults
  window.CRM_CONFIG = JSON.parse(JSON.stringify(DEFAULT_CRM_DATABASE));
  localStorage.setItem("CRM_DATABASE_STATE", JSON.stringify(window.CRM_CONFIG));
}

// Merge configuration overrides (e.g. customized branding settings)
const savedOverrides = localStorage.getItem("CRM_SETTINGS_OVERRIDE");
if (savedOverrides) {
  try {
    const parsed = JSON.parse(savedOverrides);
    if (parsed.branding) Object.assign(window.CRM_CONFIG.branding, parsed.branding);
    if (parsed.user) Object.assign(window.CRM_CONFIG.user, parsed.user);
  } catch (err) {
    console.error("Error loading CRM configuration overrides:", err);
  }
}

// Helper to write modifications back to storage and alert listeners
window.saveCrmDatabase = function() {
  localStorage.setItem("CRM_DATABASE_STATE", JSON.stringify(window.CRM_CONFIG));
  // Fire a global event so active views can react if needed
  window.dispatchEvent(new Event("crmDatabaseUpdated"));
};
