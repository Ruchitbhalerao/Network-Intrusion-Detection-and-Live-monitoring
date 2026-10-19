const REFRESH_MS = 10000;
const SEVERITY_ORDER = ["high", "medium", "low"];

let refreshing = false;
let hasLoaded = false;

const statusEl = document.getElementById("status");
const lastUpdatedEl = document.getElementById("last-updated");
const refreshButton = document.getElementById("refresh");

async function fetchJSON(path) {
  let response;
  try {
    response = await fetch(path, { headers: { Accept: "application/json" } });
  } catch (error) {
    throw new Error(`could not reach the API (${error.message})`);
  }

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      if (body && body.error) {
        detail = body.error;
      }
    } catch (error) {
      detail = `HTTP ${response.status} ${response.statusText}`.trim();
    }
    throw new Error(detail);
  }

  try {
    return await response.json();
  } catch (error) {
    throw new Error("the API returned an invalid JSON response");
  }
}

async function loadDashboard() {
  if (refreshing) {
    return;
  }
  refreshing = true;
  refreshButton.disabled = true;
  setStatus("Loading\u2026", "loading");

  try {
    const [health, alerts, devices, stats] = await Promise.all([
      fetchJSON("/api/health"),
      fetchJSON("/api/alerts"),
      fetchJSON("/api/devices"),
      fetchJSON("/api/stats"),
    ]);

    if (!health || health.status !== "ok") {
      throw new Error("the API reported an unhealthy status");
    }

    renderStats(stats);
    renderAlerts(Array.isArray(alerts.alerts) ? alerts.alerts : []);
    renderDevices(Array.isArray(devices.devices) ? devices.devices : []);

    hasLoaded = true;
    setStatus("Data loaded", "ok");
    lastUpdatedEl.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    setStatus(`Could not load data: ${error.message}`, "error");
    if (!hasLoaded) {
      renderUnavailable();
    }
  } finally {
    refreshing = false;
    refreshButton.disabled = false;
  }
}

function renderStats(stats) {
  document.getElementById("total-alerts").textContent = display(stats.total_alerts);
  document.getElementById("tracked-devices").textContent = display(stats.tracked_devices);

  const list = document.getElementById("severity-counts");
  list.replaceChildren();

  const counts = (stats && stats.alerts_by_severity) || {};
  const entries = Object.entries(counts);
  if (entries.length === 0) {
    list.appendChild(listItem("No alerts yet", "muted"));
    return;
  }

  entries.sort(
    (a, b) => severityRank(a[0]) - severityRank(b[0]) || a[0].localeCompare(b[0])
  );
  for (const [severity, count] of entries) {
    const item = document.createElement("li");
    item.appendChild(severityBadge(severity));
    const value = document.createElement("span");
    value.className = "severity-count";
    value.textContent = String(count);
    item.appendChild(value);
    list.appendChild(item);
  }
}

function renderAlerts(alerts) {
  const body = document.getElementById("alerts-body");
  body.replaceChildren();

  if (alerts.length === 0) {
    body.appendChild(emptyRow(6, "No alerts recorded yet."));
    return;
  }

  for (const alert of alerts) {
    const row = document.createElement("tr");
    row.appendChild(cell(formatTime(alert.timestamp)));

    const severity = document.createElement("td");
    severity.appendChild(severityBadge(alert.severity));
    row.appendChild(severity);

    row.appendChild(cell(display(alert.alert_type)));
    row.appendChild(cell(display(alert.src_ip)));
    row.appendChild(cell(display(alert.dst_ip)));
    row.appendChild(cell(display(alert.message)));
    body.appendChild(row);
  }
}

function renderDevices(devices) {
  const body = document.getElementById("devices-body");
  body.replaceChildren();

  if (devices.length === 0) {
    body.appendChild(emptyRow(6, "No devices tracked yet."));
    return;
  }

  for (const device of devices) {
    const row = document.createElement("tr");
    row.appendChild(cell(display(device.ip)));
    row.appendChild(cell(display(device.mac)));
    row.appendChild(cell(display(device.hostname)));
    row.appendChild(cell(display(device.label)));
    row.appendChild(cell(device.known ? "Yes" : "No"));
    row.appendChild(cell(formatTime(device.last_seen)));
    body.appendChild(row);
  }
}

function renderUnavailable() {
  document.getElementById("total-alerts").textContent = "\u2014";
  document.getElementById("tracked-devices").textContent = "\u2014";

  const list = document.getElementById("severity-counts");
  list.replaceChildren(listItem("Unavailable", "muted"));

  document
    .getElementById("alerts-body")
    .replaceChildren(emptyRow(6, "Alerts unavailable."));
  document
    .getElementById("devices-body")
    .replaceChildren(emptyRow(6, "Devices unavailable."));
}

function severityBadge(severity) {
  const badge = document.createElement("span");
  badge.className = `badge severity-${severityClass(severity)}`;
  badge.textContent = severityLabel(severity);
  return badge;
}

function severityLabel(severity) {
  const value = String(severity || "").trim();
  if (!value) {
    return "Unknown";
  }
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function severityClass(severity) {
  const value = String(severity || "").toLowerCase();
  return SEVERITY_ORDER.includes(value) ? value : "unknown";
}

function severityRank(severity) {
  const index = SEVERITY_ORDER.indexOf(String(severity || "").toLowerCase());
  return index === -1 ? SEVERITY_ORDER.length : index;
}

function cell(value) {
  const td = document.createElement("td");
  td.textContent = value;
  return td;
}

function emptyRow(columns, message) {
  const row = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = columns;
  td.className = "empty";
  td.textContent = message;
  row.appendChild(td);
  return row;
}

function listItem(message, className) {
  const item = document.createElement("li");
  item.className = className;
  item.textContent = message;
  return item;
}

function display(value) {
  if (value === null || value === undefined || value === "") {
    return "\u2014";
  }
  return String(value);
}

function formatTime(seconds) {
  if (seconds === null || seconds === undefined) {
    return "\u2014";
  }
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) {
    return String(seconds);
  }
  return date.toLocaleString();
}

function setStatus(message, kind) {
  statusEl.textContent = message;
  statusEl.className = `status status-${kind}`;
}

refreshButton.addEventListener("click", loadDashboard);
loadDashboard();
setInterval(loadDashboard, REFRESH_MS);
