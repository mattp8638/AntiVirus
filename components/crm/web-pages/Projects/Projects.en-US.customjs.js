if (typeof window.projectsHandlerInitialized === "undefined") {
  window.projectsHandlerInitialized = true;

  window.initProjectsPage = function() {
    const config = window.CRM_CONFIG;
    if (!config) return;

    const metricsGrid = document.getElementById("projects-metrics-grid");
    const tableBody = document.getElementById("projectsTableBody");

    const viewTableBtn = document.getElementById("viewTableBtn");
    const viewKanbanBtn = document.getElementById("viewKanbanBtn");
    const tableViewWrapper = document.getElementById("projects-table-view");
    const kanbanViewWrapper = document.getElementById("projects-kanban-view");

    if (viewTableBtn && viewKanbanBtn) {
      // Clear old listeners
      const newTableBtn = viewTableBtn.cloneNode(true);
      viewTableBtn.parentNode.replaceChild(newTableBtn, viewTableBtn);
      const newKanbanBtn = viewKanbanBtn.cloneNode(true);
      viewKanbanBtn.parentNode.replaceChild(newKanbanBtn, viewKanbanBtn);

      newTableBtn.addEventListener("click", () => {
        newTableBtn.style.background = "var(--accent-blue)";
        newTableBtn.style.color = "#fff";
        newKanbanBtn.style.background = "transparent";
        newKanbanBtn.style.color = "var(--text-sub)";
        tableViewWrapper.style.display = "block";
        kanbanViewWrapper.style.display = "none";
      });

      newKanbanBtn.addEventListener("click", () => {
        newKanbanBtn.style.background = "var(--accent-blue)";
        newKanbanBtn.style.color = "#fff";
        newTableBtn.style.background = "transparent";
        newTableBtn.style.color = "var(--text-sub)";
        tableViewWrapper.style.display = "none";
        kanbanViewWrapper.style.display = "flex";
        renderKanbanBoard();
      });
    }

    // Calculate project progress percentage based on tasks
    function recalculateProjectProgress(proj) {
      if (!proj.tasks || proj.tasks.length === 0) return;
      
      const completedTasks = proj.tasks.filter(t => t.status === "Done").length;
      const progress = Math.round((completedTasks / proj.tasks.length) * 100);
      
      proj.progress = progress;
      
      if (progress === 100) {
        proj.status = "Completed";
        proj.phase = "Launch Ready";
      } else if (progress <= 15) {
        proj.status = "Warning";
        proj.phase = "Phase 1: Wireframing";
      } else {
        proj.status = "Active";
        if (progress > 50) {
          proj.phase = "Phase 3: Integration";
        } else {
          proj.phase = "Phase 2: User Testing";
        }
      }
    }

    // Render Table View & KPI Metrics
    function renderProjects() {
      if (!config.projects) return;

      // 1. Recalculate progress based on task states
      config.projects.forEach(recalculateProjectProgress);

      // 2. Calculate metrics values
      const activeProjects = config.projects.filter(p => p.status === "Active").length;
      const avgProgress = Math.round(
        config.projects.reduce((sum, p) => sum + p.progress, 0) / config.projects.length
      );
      const totalHours = config.projects.length * 80;
      const blockers = config.projects.filter(p => p.status === "Warning").length;

      if (metricsGrid) {
        metricsGrid.innerHTML = `
          <div class="crm-card crm-metric-card" style="border-top: 3px solid var(--accent-blue);">
            <span class="crm-metric-label">Active Contracts</span>
            <span class="crm-metric-val">${activeProjects}</span>
            <div style="font-size: 0.8rem; color: var(--text-sub);">In continuous integration</div>
          </div>
          <div class="crm-card crm-metric-card" style="border-top: 3px solid var(--accent-green);">
            <span class="crm-metric-label">Avg Progress</span>
            <span class="crm-metric-val">${avgProgress}%</span>
            <div style="font-size: 0.8rem; color: var(--text-sub);">Across all database models</div>
          </div>
          <div class="crm-card crm-metric-card" style="border-top: 3px solid var(--accent-amber);">
            <span class="crm-metric-label">Allocated Resources</span>
            <span class="crm-metric-val">${totalHours} hrs</span>
            <div style="font-size: 0.8rem; color: var(--text-sub);">Total workload distribution</div>
          </div>
          <div class="crm-card crm-metric-card" style="border-top: 3px solid var(--accent-rose);">
            <span class="crm-metric-label">Open Blockers</span>
            <span class="crm-metric-val">${blockers}</span>
            <div style="font-size: 0.8rem; color: ${blockers > 0 ? 'var(--accent-rose)' : 'var(--accent-green)'}; font-weight: bold;">
              ${blockers > 0 ? `▲ ${blockers} warning state(s)` : '✔ All systems operational'}
            </div>
          </div>
        `;
      }

      if (tableBody) {
        tableBody.innerHTML = "";
        
        config.projects.forEach((proj, index) => {
          let badgeClass = "success";
          if (proj.status === "Completed") badgeClass = "info";
          if (proj.status === "Warning") badgeClass = "warning";
          
          let barColor = "linear-gradient(90deg, var(--accent-blue), #60a5fa)";
          if (proj.progress >= 70) {
            barColor = "linear-gradient(90deg, var(--accent-green), #34d399)";
          } else if (proj.progress <= 20) {
            barColor = "linear-gradient(90deg, var(--accent-amber), #fbbf24)";
          }

          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td>
              <div style="font-weight: 700; color: #fff;">${proj.name}</div>
              <div style="font-size: 0.8rem; color: var(--text-sub);">${proj.details}</div>
            </td>
            <td>${proj.targetDate}</td>
            <td>
              <div style="display: flex; align-items: center; gap: 10px;">
                <div class="crm-progress-track" style="flex: 1;">
                  <div class="crm-progress-bar" style="width: ${proj.progress}%; background: ${barColor};"></div>
                </div>
                <span style="font-size: 0.85rem; font-weight: bold; color: #fff;">${proj.progress}%</span>
              </div>
            </td>
            <td><span class="crm-badge ${badgeClass}">${proj.status}</span></td>
            <td style="font-weight: 600; ${proj.status === 'Completed' ? 'color: var(--accent-green);' : ''}">${proj.phase}</td>
            <td style="text-align: right;">
              <button class="crm-btn-project-edit" onclick="updateProjectProgress(${index})" style="background: rgba(255,255,255,0.04); border: 1px solid var(--border-glass); border-radius: 8px; color: #fff; padding: 6px 12px; font-size: 0.8rem; font-weight: bold; cursor: pointer; transition: all 0.3s ease;">Update</button>
            </td>
          `;
          tableBody.appendChild(tr);
        });
      }
    }

    // Update progress manually via prompt
    window.updateProjectProgress = function(index) {
      const proj = config.projects[index];
      if (!proj) return;

      const newProgress = prompt(`Enter progress percentage for ${proj.name} (0-100):`, proj.progress);
      if (newProgress === null) return;

      const percentage = parseInt(newProgress);
      if (isNaN(percentage) || percentage < 0 || percentage > 100) {
        alert("Please enter a valid number between 0 and 100.");
        return;
      }

      // Proportional task adjustments
      const doneCount = Math.round((percentage / 100) * proj.tasks.length);
      proj.tasks.forEach((t, i) => {
        if (i < doneCount) t.status = "Done";
        else t.status = "ToDo";
      });

      // Save database and show Toast
      if (window.saveCrmDatabase) window.saveCrmDatabase();
      if (window.showToast) window.showToast(`Progress for '${proj.name}' updated to ${percentage}%`, "info");

      renderProjects();
      if (kanbanViewWrapper.style.display === "flex") {
        renderKanbanBoard();
      }
    };

    // Render Kanban Board
    function renderKanbanBoard() {
      const todoList = document.getElementById("kanban-todo-list");
      const progressList = document.getElementById("kanban-progress-list");
      const doneList = document.getElementById("kanban-done-list");

      const todoCount = document.getElementById("kanban-todo-count");
      const progressCount = document.getElementById("kanban-progress-count");
      const doneCount = document.getElementById("kanban-done-count");

      if (!todoList || !progressList || !doneList) return;

      todoList.innerHTML = "";
      progressList.innerHTML = "";
      doneList.innerHTML = "";

      let counts = { ToDo: 0, InProgress: 0, Done: 0 };

      config.projects.forEach((proj, projIdx) => {
        if (!proj.tasks) return;

        proj.tasks.forEach((task, taskIdx) => {
          counts[task.status]++;

          const card = document.createElement("div");
          card.style.cssText = "background: rgba(0, 0, 0, 0.3); border: 1px solid var(--border-glass); border-radius: 12px; padding: 16px; transition: all 0.3s ease;";
          
          let actionBtn = "";
          if (task.status === "ToDo") {
            actionBtn = `<button onclick="moveTask(${projIdx}, ${taskIdx}, 'InProgress')" style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); color: var(--accent-blue); padding: 5px 12px; border-radius: 6px; font-size: 0.75rem; font-weight: bold; cursor: pointer; margin-top: 10px; width: 100%;">Start ➜</button>`;
          } else if (task.status === "InProgress") {
            actionBtn = `
              <div style="display: flex; gap: 8px; margin-top: 10px;">
                <button onclick="moveTask(${projIdx}, ${taskIdx}, 'ToDo')" style="background: transparent; border: 1px solid var(--border-glass); color: var(--text-sub); padding: 5px 8px; border-radius: 6px; font-size: 0.75rem; cursor: pointer; flex: 1;">⬅ Back</button>
                <button onclick="moveTask(${projIdx}, ${taskIdx}, 'Done')" style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); color: var(--accent-green); padding: 5px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: bold; cursor: pointer; flex: 1.5;">Complete ➜</button>
              </div>
            `;
          } else if (task.status === "Done") {
            actionBtn = `<button onclick="moveTask(${projIdx}, ${taskIdx}, 'InProgress')" style="background: transparent; border: 1px solid var(--border-glass); color: var(--text-sub); padding: 5px 12px; border-radius: 6px; font-size: 0.75rem; cursor: pointer; margin-top: 10px; width: 100%;">Restart ↺</button>`;
          }

          card.innerHTML = `
            <div style="font-weight: 700; color: #fff; font-size: 0.9rem; line-height: 1.4;">${task.name}</div>
            <div style="font-size: 0.75rem; color: var(--text-sub); margin-top: 5px; display: flex; align-items: center; gap: 6px;">
              <span style="width: 6px; height: 6px; border-radius: 50%; background: var(--accent-blue);"></span>
              ${proj.name}
            </div>
            ${actionBtn}
          `;

          if (task.status === "ToDo") todoList.appendChild(card);
          else if (task.status === "InProgress") progressList.appendChild(card);
          else if (task.status === "Done") doneList.appendChild(card);
        });
      });

      if (todoCount) todoCount.innerText = counts.ToDo;
      if (progressCount) progressCount.innerText = counts.InProgress;
      if (doneCount) doneCount.innerText = counts.Done;
    }

    // Move tasks on the Kanban board
    window.moveTask = function(projIdx, taskIdx, nextStatus) {
      const proj = config.projects[projIdx];
      if (!proj || !proj.tasks[taskIdx]) return;

      const task = proj.tasks[taskIdx];
      task.status = nextStatus;

      // Recalculate progress states
      recalculateProjectProgress(proj);

      // Save database and trigger Toast alert
      if (window.saveCrmDatabase) window.saveCrmDatabase();
      if (window.showToast) {
        let text = `Task '${task.name}' moved to In Progress`;
        if (nextStatus === "Done") text = `Task '${task.name}' completed!`;
        if (nextStatus === "ToDo") text = `Task '${task.name}' moved to To Do`;
        window.showToast(text, nextStatus === "Done" ? "success" : "info");
      }

      // Re-render
      renderProjects();
      renderKanbanBoard();
    };

    // Initial render
    renderProjects();
  };
}

if (document.getElementById("projectsTableBody")) {
  window.initProjectsPage();
}
