document.addEventListener("DOMContentLoaded", () => {
  const config = window.CRM_CONFIG;
  if (!config) return;

  const brandNameInput = document.getElementById("settingsBrandName");
  const brandShortInput = document.getElementById("settingsBrandShort");
  const usernameInput = document.getElementById("settingsUsername");
  const userRoleInput = document.getElementById("settingsUserRole");
  const colorBubbles = document.querySelectorAll(".color-preset-bubble");
  const hiddenColorInput = document.getElementById("selectedThemeColor");
  const settingsForm = document.getElementById("settingsCustomizerForm");
  const resetBtn = document.getElementById("resetDefaultsBtn");

  // 1. Populate current configuration values
  if (brandNameInput) brandNameInput.value = config.branding.name || "";
  if (brandShortInput) brandShortInput.value = config.branding.shortName || "";
  if (usernameInput) usernameInput.value = config.user.name || "";
  if (userRoleInput) userRoleInput.value = config.user.role || "";
  
  const currentAccent = config.branding.accentColor || "#3b82f6";
  if (hiddenColorInput) hiddenColorInput.value = currentAccent;

  // Set active color bubble
  colorBubbles.forEach((bubble) => {
    const bubbleColor = bubble.getAttribute("data-color");
    if (bubbleColor.toLowerCase() === currentAccent.toLowerCase()) {
      bubble.classList.add("active");
    }

    bubble.addEventListener("click", (e) => {
      // Clear active class from all
      colorBubbles.forEach(b => b.classList.remove("active"));
      
      // Set active to clicked
      bubble.classList.add("active");
      hiddenColorInput.value = bubbleColor;
    });
  });

  // 2. Handle Form Save settings
  if (settingsForm) {
    settingsForm.addEventListener("submit", (e) => {
      e.preventDefault();
      
      const brandName = brandNameInput.value;
      const brandShort = brandShortInput.value;
      const username = usernameInput.value;
      const userRole = userRoleInput.value;
      const selectedColor = hiddenColorInput.value;

      // Generate avatar initials from name
      const nameParts = username.trim().split(" ");
      let initials = "MA";
      if (nameParts.length > 1) {
        initials = (nameParts[0][0] + nameParts[nameParts.length - 1][0]).toUpperCase();
      } else if (nameParts.length === 1 && nameParts[0].length > 0) {
        initials = nameParts[0].substring(0, 2).toUpperCase();
      }

      const overrides = {
        branding: {
          name: brandName,
          shortName: brandShort,
          accentColor: selectedColor
        },
        user: {
          name: username,
          role: userRole,
          initials: initials
        }
      };

      // Save overrides to localStorage
      localStorage.setItem("CRM_SETTINGS_OVERRIDE", JSON.stringify(overrides));
      
      alert("System configurations updated successfully! Reloading to apply changes...");
      window.location.reload();
    });
  }

  // 3. Handle Reset Settings Defaults
  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      if (confirm("Are you sure you want to revert all system customizations back to default values?")) {
        localStorage.removeItem("CRM_SETTINGS_OVERRIDE");
        alert("System configurations reset to system defaults. Reloading...");
        window.location.reload();
      }
    });
  }
});
