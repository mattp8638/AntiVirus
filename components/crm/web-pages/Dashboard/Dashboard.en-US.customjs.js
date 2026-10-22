document.addEventListener("DOMContentLoaded", () => {
  const config = window.CRM_CONFIG;
  if (!config) return;

  // 1. Bind Username
  const welcomeUsername = document.getElementById("welcome-username");
  if (welcomeUsername && config.user.name) {
    welcomeUsername.innerText = config.user.name.split(" ")[0];
  }

  // 2. Calculate dynamic metrics
  const totalRevenue = config.invoices
    .filter(inv => inv.status === "Paid")
    .reduce((sum, inv) => sum + inv.amount, 0);

  const activeLeadsCount = config.leads
    .filter(lead => lead.stage !== "Lost").length;

  const activeProjectsCount = config.projects
    .filter(proj => proj.status === "Active").length;

  const openTicketsCount = config.tickets
    .filter(tkt => tkt.status !== "Resolved").length;

  // 3. Render KPI Metric Grid
  const kpiGrid = document.getElementById("kpi-metrics-grid");
  if (kpiGrid) {
    kpiGrid.innerHTML = `
      <!-- Metric 1 -->
      <div class="crm-card crm-metric-card" style="border-left: 4px solid var(--accent-green);">
        <span class="crm-metric-label">Monthly Revenue</span>
        <span class="crm-metric-val">$${totalRevenue.toLocaleString()}</span>
        <div class="crm-metric-change" style="color: var(--accent-green);">
          <span>▲ +12.4%</span> <span style="color: var(--text-sub); font-weight: normal;">this month</span>
        </div>
      </div>
      <!-- Metric 2 -->
      <div class="crm-card crm-metric-card" style="border-left: 4px solid var(--accent-blue);">
        <span class="crm-metric-label">Active Leads</span>
        <span class="crm-metric-val">${activeLeadsCount}</span>
        <div class="crm-metric-change" style="color: var(--accent-blue);">
          <span>▲ +5.2%</span> <span style="color: var(--text-sub); font-weight: normal;">conversion rate</span>
        </div>
      </div>
      <!-- Metric 3 -->
      <div class="crm-card crm-metric-card" style="border-left: 4px solid var(--accent-amber);">
        <span class="crm-metric-label">Active Projects</span>
        <span class="crm-metric-val">${activeProjectsCount}</span>
        <div class="crm-metric-change" style="color: var(--accent-amber);">
          <span>● 3 Pending</span> <span style="color: var(--text-sub); font-weight: normal;">milestones</span>
        </div>
      </div>
      <!-- Metric 4 -->
      <div class="crm-card crm-metric-card" style="border-left: 4px solid var(--accent-rose);">
        <span class="crm-metric-label">Support Tickets</span>
        <span class="crm-metric-val">${openTicketsCount}</span>
        <div class="crm-metric-change" style="color: var(--accent-rose);">
          <span>▼ 2 Urgent</span> <span style="color: var(--text-sub); font-weight: normal;">awaiting response</span>
        </div>
      </div>
    `;
  }

  // 4. Render Dynamic SVG Revenue Chart
  const chartContainer = document.getElementById("revenue-chart-container");
  if (chartContainer) {
    // We will draw a premium glowing SVG line chart
    chartContainer.innerHTML = `
      <svg width="100%" height="100%" viewBox="0 0 1000 200" preserveAspectRatio="none" style="overflow: visible;">
        <defs>
          <!-- Grid Line Linear Gradients -->
          <linearGradient id="chart-glow" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="var(--accent-blue)" stop-opacity="0.3"/>
            <stop offset="100%" stop-color="var(--accent-blue)" stop-opacity="0"/>
          </linearGradient>
          <filter id="glow-effect" x="-20%" y="-20%" width="140%" height="140%">
            <feDropShadow dx="0" dy="8" stdDeviation="6" flood-color="var(--accent-blue)" flood-opacity="0.5"/>
          </filter>
        </defs>
        
        <!-- Y-Axis Grid Lines -->
        <line x1="50" y1="20" x2="950" y2="20" stroke="rgba(255,255,255,0.03)" stroke-width="1" />
        <line x1="50" y1="75" x2="950" y2="75" stroke="rgba(255,255,255,0.03)" stroke-width="1" />
        <line x1="50" y1="130" x2="950" y2="130" stroke="rgba(255,255,255,0.03)" stroke-width="1" />
        <line x1="50" y1="185" x2="950" y2="185" stroke="rgba(255,255,255,0.08)" stroke-width="1" stroke-dasharray="5 5" />
        
        <!-- Filling area below the path -->
        <path d="M 50 185 L 50 150 Q 200 130 350 90 T 650 65 T 950 30 L 950 185 Z" fill="url(#chart-glow)"></path>
        
        <!-- Glowing Line Path -->
        <path d="M 50 150 Q 200 130 350 90 T 650 65 T 950 30" fill="none" stroke="var(--accent-blue)" stroke-width="4" filter="url(#glow-effect)" style="stroke-dasharray: 1000; stroke-dashoffset: 1000; animation: drawLine 2s cubic-bezier(0.4, 0, 0.2, 1) forwards;"></path>
        
        <!-- Grid Nodes (Interactive Indicators) -->
        <circle cx="50" cy="150" r="6" fill="#fff" stroke="var(--accent-blue)" stroke-width="3" style="cursor: pointer;"></circle>
        <circle cx="350" cy="90" r="6" fill="#fff" stroke="var(--accent-blue)" stroke-width="3" style="cursor: pointer;"></circle>
        <circle cx="650" cy="65" r="6" fill="#fff" stroke="var(--accent-blue)" stroke-width="3" style="cursor: pointer;"></circle>
        <circle cx="950" cy="30" r="6" fill="#fff" stroke="var(--accent-blue)" stroke-width="3" style="cursor: pointer;"></circle>

        <!-- X-Axis Labels -->
        <text x="50" y="215" fill="var(--text-sub)" font-size="12" font-weight="600" text-anchor="middle">APR ($18k)</text>
        <text x="350" y="215" fill="var(--text-sub)" font-size="12" font-weight="600" text-anchor="middle">MAY ($29k)</text>
        <text x="650" y="215" fill="var(--text-sub)" font-size="12" font-weight="600" text-anchor="middle">JUN ($36k)</text>
        <text x="950" y="215" fill="var(--text-sub)" font-size="12" font-weight="600" text-anchor="middle">JUL ($${Math.round(totalRevenue/1000)}k)</text>
      </svg>
      <style>
        @keyframes drawLine {
          to {
            stroke-dashoffset: 0;
          }
        }
      </style>
    `;
  }

  // 5. Render Activity Timeline
  const timelineContainer = document.getElementById("dashboard-timeline");
  if (timelineContainer && config.timeline) {
    timelineContainer.innerHTML = "";
    config.timeline.forEach((item) => {
      let colorClass = "var(--accent-blue)";
      if (item.type === "success") colorClass = "var(--accent-green)";
      if (item.type === "warning") colorClass = "var(--accent-amber)";
      if (item.type === "danger") colorClass = "var(--accent-rose)";

      const timelineItem = document.createElement("div");
      timelineItem.className = "crm-timeline-item";
      timelineItem.style.position = "relative";
      timelineItem.innerHTML = `
        <div style="position: absolute; left: -27px; top: 4px; width: 12px; height: 12px; border-radius: 50%; background: ${colorClass}; box-shadow: 0 0 10px ${colorClass};"></div>
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
          <strong style="color: #fff; font-size: 0.95rem;">${item.title}</strong>
          <span style="font-size: 0.75rem; color: var(--text-sub);">${item.time}</span>
        </div>
        <p style="margin: 5px 0 0 0; font-size: 0.85rem; color: var(--text-sub);">${item.text}</p>
      `;
      timelineContainer.appendChild(timelineItem);
    });
  }

  // 6. Render Active Deliverables
  const deliverablesContainer = document.getElementById("deliverables-list");
  if (deliverablesContainer && config.projects) {
    deliverablesContainer.innerHTML = "";
    
    // Sort projects to display active/incomplete ones first
    const activeProjects = config.projects
      .filter(p => p.status === "Active" || p.progress < 100)
      .slice(0, 3); // Take top 3

    activeProjects.forEach((proj) => {
      let barColor = "linear-gradient(90deg, var(--accent-blue), #60a5fa)";
      let textColor = "var(--accent-blue)";
      if (proj.progress >= 70) {
        barColor = "linear-gradient(90deg, var(--accent-green), #34d399)";
        textColor = "var(--accent-green)";
      } else if (proj.progress <= 20) {
        barColor = "linear-gradient(90deg, var(--accent-amber), #fbbf24)";
        textColor = "var(--accent-amber)";
      }

      const item = document.createElement("div");
      item.innerHTML = `
        <div style="display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 8px;">
          <span style="font-weight: 600; color: #fff;">${proj.name}</span>
          <span style="color: ${textColor}; font-weight: 700;">${proj.progress}%</span>
        </div>
        <div class="crm-progress-track">
          <div class="crm-progress-bar" style="width: ${proj.progress}%; background: ${barColor};"></div>
        </div>
      `;
      deliverablesContainer.appendChild(item);
    });
  }

  // 7. Perform count-up numerical animations on load
  const metricValues = document.querySelectorAll(".crm-metric-val");
  metricValues.forEach((val) => {
    const rawText = val.innerText.replace(/[^0-9.]/g, "");
    if (!rawText) return;
    
    const targetValue = parseFloat(rawText);
    let startValue = 0;
    const isCurrency = val.innerText.startsWith("$");
    const duration = 1000; // ms
    const stepTime = 30;
    const steps = duration / stepTime;
    const increment = targetValue / steps;
    
    const counter = setInterval(() => {
      startValue += increment;
      if (startValue >= targetValue) {
        val.innerText = isCurrency ? `$${targetValue.toLocaleString()}` : targetValue;
        clearInterval(counter);
      } else {
        const rounded = Math.floor(startValue);
        val.innerText = isCurrency ? `$${rounded.toLocaleString()}` : rounded;
      }
    }, stepTime);
  });
});
