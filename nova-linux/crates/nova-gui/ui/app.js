// Nova Linux GUI Client Script

document.addEventListener("DOMContentLoaded", () => {
  const powerToggleBtn = document.getElementById("powerToggleBtn");
  const heroStatus = document.getElementById("heroStatus");
  const statusTitle = document.getElementById("statusTitle");
  const statusSubtitle = document.getElementById("statusSubtitle");
  const logToggleBtn = document.getElementById("logToggleBtn");
  const logDrawer = document.getElementById("logDrawer");
  const logArrow = document.getElementById("logArrow");
  const clearLogsBtn = document.getElementById("clearLogsBtn");
  const logFeed = document.getElementById("logFeed");
  const minimizeBtn = document.getElementById("minimizeBtn");
  const closeBtn = document.getElementById("closeBtn");
  const profileSelectorBtn = document.getElementById("profileSelectorBtn");

  let isEnabled = true;
  let isLogsOpen = false;

  // Window action buttons
  if (window.__TAURI__) {
    const { getCurrentWindow } = window.__TAURI__.window;
    const appWindow = getCurrentWindow();

    minimizeBtn.addEventListener("click", () => {
      appWindow.minimize();
    });

    closeBtn.addEventListener("click", () => {
      // By default, closing the window hides it to tray rather than exiting
      appWindow.hide();
    });
  } else {
    minimizeBtn.addEventListener("click", () => console.log("Minimize clicked"));
    closeBtn.addEventListener("click", () => console.log("Close clicked"));
  }

  // Power toggle (Enable / Disable bypass)
  powerToggleBtn.addEventListener("click", () => {
    isEnabled = !isEnabled;
    if (isEnabled) {
      powerToggleBtn.classList.add("active");
      heroStatus.classList.remove("disabled");
      statusTitle.textContent = "ПОДКЛЮЧЕНО";
      statusSubtitle.textContent = "Адаптивный обход активен";
      appendLog("SYS", "Обход трафика активирован пользователем", "success");
    } else {
      powerToggleBtn.classList.remove("active");
      heroStatus.classList.add("disabled");
      statusTitle.textContent = "ОТКЛЮЧЕНО";
      statusSubtitle.textContent = "Прямой доступ без обхода DPI";
      appendLog("SYS", "Обход временно отключен (Paused)", "warn");
    }

    if (window.__TAURI__ && window.__TAURI__.core) {
      window.__TAURI__.core.invoke("set_network_mode", {
        mode: isEnabled ? "adaptive" : "paused"
      }).catch(err => {
        console.error("Failed to toggle mode:", err);
      });
    }
  });

  // Log drawer toggle
  logToggleBtn.addEventListener("click", () => {
    isLogsOpen = !isLogsOpen;
    if (isLogsOpen) {
      logDrawer.classList.remove("collapsed");
      logArrow.textContent = "▼";
    } else {
      logDrawer.classList.add("collapsed");
      logArrow.textContent = "▲";
    }
  });

  clearLogsBtn.addEventListener("click", () => {
    logFeed.innerHTML = "";
  });

  // Profile Selector cycle: Auto -> Direct DPI -> WARP Only
  const profiles = ["⚡ Авто", "🛡 Прямой DPI", "🌐 WARP Туннель"];
  let currentProfileIdx = 0;

  profileSelectorBtn.addEventListener("click", () => {
    currentProfileIdx = (currentProfileIdx + 1) % profiles.length;
    profileSelectorBtn.textContent = profiles[currentProfileIdx];
    appendLog("CFG", `Профиль переключен на: ${profiles[currentProfileIdx]}`, "info");
  });

  function appendLog(badge, message, type = "info") {
    const row = document.createElement("div");
    row.className = `log-row ${type}`;
    
    const now = new Date();
    const timeStr = [
      String(now.getHours()).padStart(2, "0"),
      String(now.getMinutes()).padStart(2, "0"),
      String(now.getSeconds()).padStart(2, "0")
    ].join(":");

    row.innerHTML = `
      <span class="log-time">${timeStr}</span>
      <span class="log-badge">${badge}</span>
      <span class="log-text">${escapeHtml(message)}</span>
    `;

    logFeed.appendChild(row);
    logFeed.scrollTop = logFeed.scrollHeight;
  }

  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }

  // Simulated live updates if running in standalone preview
  setInterval(() => {
    if (!isEnabled) return;
    const pingEl = document.getElementById("latencyStat");
    if (pingEl) {
      const ping = Math.floor(22 + Math.random() * 12);
      pingEl.textContent = `⚡ ${ping} ms`;
    }
  }, 4000);
});
