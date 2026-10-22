if (typeof window.invoicesHandlerInitialized === "undefined") {
  window.invoicesHandlerInitialized = true;

  window.initInvoicesPage = function() {
    const config = window.CRM_CONFIG;
    if (!config) return;

    const metricsGrid = document.getElementById("invoices-metrics-grid");
    const tableBody = document.getElementById("invoicesTableBody");

    // Render function
    function renderInvoices() {
      if (!config.invoices) return;

      // 1. Calculate metrics values
      const outstanding = config.invoices
        .filter(inv => inv.status === "Unpaid" || inv.status === "Overdue")
        .reduce((sum, inv) => sum + inv.amount, 0);

      const paid = config.invoices
        .filter(inv => inv.status === "Paid")
        .reduce((sum, inv) => sum + inv.amount, 0);

      const overdueCount = config.invoices
        .filter(inv => inv.status === "Overdue").length;

      // Render metrics
      if (metricsGrid) {
        metricsGrid.innerHTML = `
          <div class="crm-card crm-metric-card" style="border-top: 3px solid var(--accent-amber);">
            <span class="crm-metric-label">Total Outstanding</span>
            <span class="crm-metric-val">$${outstanding.toLocaleString()}</span>
            <div style="font-size: 0.8rem; color: var(--text-sub);">Across unpaid billings</div>
          </div>
          <div class="crm-card crm-metric-card" style="border-top: 3px solid var(--accent-green);">
            <span class="crm-metric-label">Total Paid</span>
            <span class="crm-metric-val">$${paid.toLocaleString()}</span>
            <div style="font-size: 0.8rem; color: var(--accent-green); font-weight: bold;">▲ +8.5% this quarter</div>
          </div>
          <div class="crm-card crm-metric-card" style="border-top: 3px solid var(--accent-rose);">
            <span class="crm-metric-label">Overdue Bills</span>
            <span class="crm-metric-val">${overdueCount}</span>
            <div style="font-size: 0.8rem; color: var(--accent-rose); font-weight: bold;">Awaiting payment actions</div>
          </div>
          <div class="crm-card crm-metric-card" style="border-top: 3px solid var(--accent-blue);">
            <span class="crm-metric-label">Next Recurring Run</span>
            <span class="crm-metric-val">15 Jul</span>
            <div style="font-size: 0.8rem; color: var(--text-sub);">Automated retainer cycles</div>
          </div>
        `;
      }

      // Render table rows
      if (tableBody) {
        tableBody.innerHTML = "";
        
        config.invoices.forEach((inv) => {
          let badgeClass = "success";
          if (inv.status === "Unpaid") badgeClass = "warning";
          if (inv.status === "Overdue") badgeClass = "danger";

          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td style="font-weight: 700; color: #fff;">${inv.id}</td>
            <td>
              <div style="font-weight: 600;">${inv.client}</div>
              <div style="font-size: 0.75rem; color: var(--text-sub);">${inv.details}</div>
            </td>
            <td style="font-weight: 600; color: #fff;">$${inv.amount.toLocaleString()}</td>
            <td>${inv.dueDate}</td>
            <td><span class="crm-badge ${badgeClass}">${inv.status}</span></td>
            <td>${inv.paymentDate}</td>
            <td style="text-align: right;">
              ${inv.status === "Paid" 
                ? `<button class="crm-btn-invoice-action" title="View PDF" onclick="viewInvoicePdf('${inv.id}')"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg></button>`
                : `<button class="crm-btn-invoice-action" title="Record Payment" onclick="recordInvoicePayment('${inv.id}')"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-green)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg></button>`
              }
            </td>
          `;
          tableBody.appendChild(tr);
        });
      }
    }

    // View PDF attachment
    window.viewInvoicePdf = function(invoiceId) {
      if (window.showToast) {
        window.showToast(`Downloading PDF for invoice ${invoiceId}...`, "info");
      }
    };

    // Process invoice payment
    window.recordInvoicePayment = function(invoiceId) {
      const inv = config.invoices.find(i => i.id === invoiceId);
      if (!inv) return;

      inv.status = "Paid";
      inv.paymentDate = "Today";

      // Save database and show Toast alert
      if (window.saveCrmDatabase) window.saveCrmDatabase();
      if (window.showToast) {
        window.showToast(`Invoice ${invoiceId} ($${inv.amount.toLocaleString()}) marked as paid`, "success");
      }

      // Re-render
      renderInvoices();
    };

    // Initial render
    renderInvoices();
  };
}

if (document.getElementById("invoicesTableBody")) {
  window.initInvoicesPage();
}
