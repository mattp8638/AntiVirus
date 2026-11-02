if (typeof window.supportHandlerInitialized === "undefined") {
  window.supportHandlerInitialized = true;

  window.initSupportPage = function() {
    const config = window.CRM_CONFIG;
    if (!config) return;

    const metricsGrid = document.getElementById("support-metrics-grid");
    const ticketsContainer = document.getElementById("ticketsList");
    const logsContainer = document.getElementById("chatLogsContainer");
    const chatTitle = document.getElementById("chatTicketTitle");
    const chatSubtitle = document.getElementById("chatTicketSubtitle");
    const resolveBtn = document.getElementById("resolveTicketBtn");
    const replyInput = document.getElementById("chatReplyInput");
    const sendBtn = document.getElementById("sendReplyBtn");

    let currentTicketId = null;

    // Render Metrics and Left List
    function renderSupport() {
      if (!config.tickets) return;

      const openTickets = config.tickets.filter(t => t.status !== "Resolved").length;
      const criticalCount = config.tickets.filter(t => t.priority === "Critical" && t.status !== "Resolved").length;

      // Render metrics
      if (metricsGrid) {
        metricsGrid.innerHTML = `
          <div class="crm-card crm-metric-card" style="border-left: 4px solid var(--accent-blue);">
            <span class="crm-metric-label">Open Tickets</span>
            <span class="crm-metric-val">${openTickets}</span>
            <div style="font-size: 0.8rem; color: var(--text-sub);">1 resolved today</div>
          </div>
          <div class="crm-card crm-metric-card" style="border-left: 4px solid var(--accent-rose);">
            <span class="crm-metric-label">Critical Priority</span>
            <span class="crm-metric-val">${criticalCount}</span>
            <div style="font-size: 0.8rem; color: ${criticalCount > 0 ? 'var(--accent-rose)' : 'var(--accent-green)'}; font-weight: bold;">
              ${criticalCount > 0 ? 'Requires immediate action' : '✔ All clear'}
            </div>
          </div>
          <div class="crm-card crm-metric-card" style="border-left: 4px solid var(--accent-green);">
            <span class="crm-metric-label">Avg Solve Time</span>
            <span class="crm-metric-val">1.5h</span>
            <div style="font-size: 0.8rem; color: var(--text-sub);">Response time metric</div>
          </div>
          <div class="crm-card crm-metric-card" style="border-left: 4px solid var(--accent-green);">
            <span class="crm-metric-label">CSAT Score</span>
            <span class="crm-metric-val">98%</span>
            <div style="font-size: 0.8rem; color: var(--text-sub);">Client satisfaction index</div>
          </div>
        `;
      }

      // Render left column tickets list
      if (ticketsContainer) {
        ticketsContainer.innerHTML = "";

        config.tickets.forEach((tkt) => {
          let borderAccent = "var(--accent-blue)";
          let badgeClass = "info";
          if (tkt.priority === "Critical") { borderAccent = "var(--accent-rose)"; badgeClass = "danger"; }
          if (tkt.priority === "Medium") { borderAccent = "var(--accent-amber)"; badgeClass = "warning"; }

          const item = document.createElement("div");
          const isActive = currentTicketId === tkt.id;

          item.className = `crm-card crm-ticket-item ${isActive ? 'active' : ''}`;
          item.style.cssText = `cursor: pointer; padding: 20px; border-left: 4px solid ${borderAccent};`;
          item.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
              <strong style="color: #fff; font-size: 0.95rem;">${tkt.title}</strong>
              <span class="crm-badge ${badgeClass}" style="padding: 3px 8px; font-size: 0.65rem;">${tkt.priority}</span>
            </div>
            <div style="font-size: 0.8rem; color: var(--text-sub); margin-bottom: 10px;">${tkt.account} • Ticket #${tkt.ticketCode}</div>
            <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.75rem;">
              <span style="color: ${tkt.status === 'Resolved' ? 'var(--accent-green)' : (tkt.status === 'Active Chat' ? 'var(--accent-rose)' : 'var(--text-sub)')}; font-weight: bold;">
                ${tkt.status === 'Resolved' ? '✔ Resolved' : `● ${tkt.status}`}
              </span>
              <span>${tkt.updatedText}</span>
            </div>
          `;

          // Override layout click
          item.addEventListener("click", () => selectTicket(tkt.id));
          ticketsContainer.appendChild(item);
        });
      }
    }

    // Load ticket details
    window.selectTicket = function(ticketId) {
      currentTicketId = ticketId;
      const ticket = config.tickets.find(t => t.id === ticketId);
      if (!ticket) return;

      // Refresh left column selections
      renderSupport();

      // Bind chat headers
      chatTitle.innerText = ticket.title;
      chatSubtitle.innerText = `${ticket.account} • Ticket #${ticket.ticketCode}`;

      // Bind conversation
      logsContainer.innerHTML = "";
      if (ticket.status === "Resolved") {
        logsContainer.innerHTML = `<div style="text-align: center; color: var(--accent-green); font-weight: bold; margin-top: 100px;">✔ This ticket has been marked as resolved.</div>`;
        replyInput.disabled = true;
        sendBtn.disabled = true;
        resolveBtn.style.display = "none";
      } else {
        ticket.messages.forEach((msg) => {
          appendMsgBubble(msg.sender, msg.initials, msg.name, msg.time, msg.text);
        });
        replyInput.disabled = false;
        sendBtn.disabled = false;
        resolveBtn.style.display = "block";
      }
    };

    function appendMsgBubble(sender, initials, name, time, text) {
      const msgDiv = document.createElement("div");
      
      if (sender === "agent") {
        msgDiv.style.cssText = "display: flex; gap: 12px; align-items: flex-start; max-width: 85%; align-self: flex-end; flex-direction: row-reverse;";
        msgDiv.innerHTML = `
          <div style="width: 32px; height: 32px; border-radius: 50%; background: var(--accent-green); display: flex; align-items: center; justify-content: center; font-weight: bold; color: #fff; font-size: 0.75rem;">${initials}</div>
          <div>
            <div style="background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); padding: 12px 16px; border-radius: 16px 0 16px 16px; font-size: 0.9rem; line-height: 1.5; color: #e5e7eb;">
              ${text}
            </div>
            <span style="font-size: 0.7rem; color: var(--text-sub); text-align: right; margin-right: 5px; margin-top: 5px; display: block;">${name} • ${time}</span>
          </div>
        `;
      } else {
        msgDiv.style.cssText = "display: flex; gap: 12px; align-items: flex-start; max-width: 85%;";
        msgDiv.innerHTML = `
          <div style="width: 32px; height: 32px; border-radius: 50%; background: #3b82f6; display: flex; align-items: center; justify-content: center; font-weight: bold; color: #fff; font-size: 0.75rem;">${initials}</div>
          <div>
            <div style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-glass); padding: 12px 16px; border-radius: 0 16px 16px 16px; font-size: 0.9rem; line-height: 1.5; color: #e5e7eb;">
              ${text}
            </div>
            <span style="font-size: 0.7rem; color: var(--text-sub); margin-left: 5px; margin-top: 5px; display: block;">${name} • ${time}</span>
          </div>
        `;
      }

      logsContainer.appendChild(msgDiv);
      logsContainer.scrollTop = logsContainer.scrollHeight;
    }

    // Send Agent Reply
    function sendAgentReply() {
      if (currentTicketId === null) return;
      const text = replyInput.value.trim();
      if (!text) return;

      const ticket = config.tickets.find(t => t.id === currentTicketId);
      if (!ticket) return;

      const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const msg = { sender: "agent", initials: "MA", name: "Agent (Matt)", time: time, text: text };
      
      // Save to config array
      ticket.messages.push(msg);

      // Save database and trigger Success Toast alert
      if (window.saveCrmDatabase) window.saveCrmDatabase();
      if (window.showToast) window.showToast("Reply sent to client", "success");

      // Render bubble and reset
      appendMsgBubble(msg.sender, msg.initials, msg.name, msg.time, msg.text);
      replyInput.value = "";
    }

    // Bind send events (clone to prevent duplicate binding in SPA reloads)
    if (sendBtn) {
      const newSend = sendBtn.cloneNode(true);
      sendBtn.parentNode.replaceChild(newSend, sendBtn);
      newSend.addEventListener("click", sendAgentReply);
    }
    
    if (replyInput) {
      const newReplyInput = replyInput.cloneNode(true);
      replyInput.parentNode.replaceChild(newReplyInput, replyInput);
      newReplyInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") sendAgentReply();
      });
    }

    // Resolve Ticket Action
    if (resolveBtn) {
      const newResolve = resolveBtn.cloneNode(true);
      resolveBtn.parentNode.replaceChild(newResolve, resolveBtn);
      
      newResolve.addEventListener("click", () => {
        if (currentTicketId === null) return;
        const ticket = config.tickets.find(t => t.id === currentTicketId);
        if (!ticket) return;

        ticket.status = "Resolved";
        
        // Save database and show Toast alert
        if (window.saveCrmDatabase) window.saveCrmDatabase();
        if (window.showToast) window.showToast(`Ticket #${ticket.ticketCode} marked as Resolved`, "success");

        // Update UI states
        selectTicket(currentTicketId);
        renderSupport();
      });
    }

    // Initial render
    renderSupport();
    if (config.tickets && config.tickets.length > 0) {
      selectTicket(config.tickets[0].id);
    }
  };
}

if (document.getElementById("ticketsList")) {
  window.initSupportPage();
}
