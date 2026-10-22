if (typeof window.leadsHandlerInitialized === "undefined") {
  window.leadsHandlerInitialized = true;
  
  // Define helper function to set up Leads events
  window.initLeadsPage = function() {
    const config = window.CRM_CONFIG;
    if (!config) return;

    const toggleBtn = document.getElementById("toggleIntakeBtn");
    const cancelBtn = document.getElementById("cancelIntakeBtn");
    const intakeCard = document.getElementById("leadIntakeCard");
    const newLeadForm = document.getElementById("newLeadForm");
    const tableBody = document.getElementById("leadsTableBody");
    
    // Render function
    function renderLeadsTable(leadsData = config.leads) {
      if (!tableBody) return;
      tableBody.innerHTML = "";
      
      leadsData.forEach((lead) => {
        let badgeClass = "info";
        if (lead.stage === "Qualified") badgeClass = "success";
        if (lead.stage === "New") badgeClass = "warning";
        if (lead.stage === "Lost") badgeClass = "danger";

        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>
            <div style="font-weight: 700; color: #fff;">${lead.company}</div>
            <div style="font-size: 0.8rem; color: var(--text-sub);">${lead.contact}</div>
          </td>
          <td>${lead.email}</td>
          <td style="font-weight: 600; color: #fff;">$${lead.value.toLocaleString()}</td>
          <td><span class="crm-badge ${badgeClass}">${lead.stage}</span></td>
          <td>${lead.date}</td>
          <td style="text-align: right;">
            <button class="crm-btn-icon" title="Email ${lead.contact}" onclick="emailLead('${lead.email}', '${lead.contact}')" ${lead.stage === 'Lost' ? 'disabled style="opacity: 0.3;"' : ''}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-blue)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
            </button>
          </td>
        `;
        tableBody.appendChild(tr);
      });
    }

    // Email click simulation via Toast
    window.emailLead = function(email, contact) {
      if (window.showToast) {
        window.showToast(`Opening mail client draft to ${contact}...`, "info");
      } else {
        alert(`Opening mail draft to ${contact} (${email})...`);
      }
    };

    // Toggle intake forms
    if (toggleBtn && intakeCard) {
      // Clear old listeners by cloning
      const newToggle = toggleBtn.cloneNode(true);
      toggleBtn.parentNode.replaceChild(newToggle, toggleBtn);
      newToggle.addEventListener("click", () => {
        intakeCard.style.display = intakeCard.style.display === "none" ? "block" : "none";
      });
    }

    if (cancelBtn && intakeCard) {
      const newCancel = cancelBtn.cloneNode(true);
      cancelBtn.parentNode.replaceChild(newCancel, cancelBtn);
      newCancel.addEventListener("click", () => {
        intakeCard.style.display = "none";
        newLeadForm.reset();
      });
    }

    // Handle lead creation
    if (newLeadForm) {
      newLeadForm.addEventListener("submit", (e) => {
        e.preventDefault();
        
        const name = document.getElementById("leadName").value;
        const company = document.getElementById("leadCompany").value;
        const email = document.getElementById("leadEmail").value;
        const stage = document.getElementById("leadStatus").value;
        const value = document.getElementById("leadValue").value || "0";
        
        const newLead = {
          company: company,
          contact: name,
          email: email,
          value: parseInt(value),
          stage: stage,
          date: "Today"
        };

        // Push to local config memory
        config.leads.unshift(newLead);
        
        // Write to persistent database
        if (window.saveCrmDatabase) window.saveCrmDatabase();

        // Trigger Success Toast
        if (window.showToast) {
          window.showToast(`Lead for '${company}' added to CRM pipeline`, "success");
        }

        // Re-render and reset
        renderLeadsTable();
        newLeadForm.reset();
        intakeCard.style.display = "none";
      });
    }

    // Search and Filter functionality
    const searchInput = document.getElementById("leadSearchInput");
    const stageFilter = document.getElementById("stageFilter");

    function filterLeads() {
      const query = searchInput.value.toLowerCase();
      const filterVal = stageFilter.value;

      const filtered = config.leads.filter((lead) => {
        const matchesSearch = lead.company.toLowerCase().includes(query) || 
                              lead.contact.toLowerCase().includes(query) || 
                              lead.email.toLowerCase().includes(query);
        const matchesStage = filterVal === "All" || lead.stage === filterVal;
        return matchesSearch && matchesStage;
      });

      renderLeadsTable(filtered);
    }

    if (searchInput) searchInput.addEventListener("input", filterLeads);
    if (stageFilter) stageFilter.addEventListener("change", filterLeads);

    // Initial render
    renderLeadsTable();
  };
}

// Auto-run if elements exist on page load
if (document.getElementById("leadsTableBody")) {
  window.initLeadsPage();
}
