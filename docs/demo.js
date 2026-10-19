const SEVERITY_ORDER = ["high", "medium", "low"];

function sampleAlerts() {
  const now = Math.floor(Date.now() / 1000);
  return [
    {
      alert_type: "port_scan",
      severity: "high",
      message:
        "Possible port scan: 24 unique destination ports from 10.0.0.37 within 10s",
      timestamp: now - 8,
      src_ip: "10.0.0.37",
      dst_ip: "10.0.0.2",
      src_port: 40000,
      dst_port: 23,
      protocol: "TCP",
    },
    {
      alert_type: "arp_anomaly",
      severity: "high",
      message:
        "ARP anomaly: 10.0.0.1 was seen with MAC aa:bb:cc:dd:ee:ff but now claims 11:22:33:44:55:66",
      timestamp: now - 22,
      src_ip: "10.0.0.1",
      dst_ip: "10.0.0.254",
      src_port: null,
      dst_port: null,
      protocol: "ARP",
    },
    {
      alert_type: "traffic_anomaly",
      severity: "medium",
      message:
        "Traffic anomaly: 250 packets from 10.0.0.37 within 5s (threshold 200)",
      timestamp: now - 35,
      src_ip: "10.0.0.37",
      dst_ip: "10.0.0.2",
      src_port: 1234,
      dst_port: 80,
      protocol: "TCP",
    },
    {
      alert_type: "unknown_device",
      severity: "medium",
      message:
        "Unknown device: 192.168.7.50 (3c:22:fb:1a:9e:04) is not in the known-device inventory",
      timestamp: now - 51,
      src_ip: "192.168.7.50",
      dst_ip: "192.168.1.1",
      src_port: 50000,
      dst_port: 22,
      protocol: "TCP",
    },
    {
      alert_type: "repeated_connections",
      severity: "medium",
      message:
        "Repeated connection attempts: 12 times from 192.168.7.50 to 192.168.1.1:22 within 30s",
      timestamp: now - 73,
      src_ip: "192.168.7.50",
      dst_ip: "192.168.1.1",
      src_port: 40011,
      dst_port: 22,
      protocol: "TCP",
    },
  ];
}

function sampleDevices() {
  const now = Math.floor(Date.now() / 1000);
  return [
    {
      ip: "10.0.0.1",
      mac: "aa:bb:cc:dd:ee:ff",
      hostname: "gateway.local",
      label: "Router",
      known: true,
      first_seen: now - 3600,
      last_seen: now - 22,
    },
    {
      ip: "10.0.0.37",
      mac: "de:ad:be:ef:00:37",
      hostname: null,
      label: null,
      known: false,
      first_seen: now - 90,
      last_seen: now - 8,
    },
    {
      ip: "192.168.7.50",
      mac: "3c:22:fb:1a:9e:04",
      hostname: null,
      label: null,
      known: false,
      first_seen: now - 120,
      last_seen: now - 51,
    },
  ];
}

function statsFrom(alerts, devices) {
  const bySeverity = {};
  for (const alert of alerts) {
    const key = String(alert.severity || "unknown").toLowerCase();
    bySeverity[key] = (bySeverity[key] || 0) + 1;
  }
  return {
    total_alerts: alerts.length,
    alerts_by_severity: bySeverity,
    tracked_devices: devices.length,
  };
}

function render() {
  const alerts = sampleAlerts();
  const devices = sampleDevices();
  renderStats(statsFrom(alerts, devices));
  renderAlerts(alerts);
  renderDevices(devices);
  document.getElementById("last-updated").textContent =
    `Last updated: ${new Date().toLocaleTimeString()}`;
}

function renderStats(stats) {
  document.getElementById("total-alerts").textContent = display(stats.total_alerts);
  document.getElementById("tracked-devices").textContent = display(
    stats.tracked_devices
  );

  const list = document.getElementById("severity-counts");
  list.replaceChildren();

  const entries = Object.entries(stats.alerts_by_severity || {});
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

function severityBadge(severity) {
  const badge = document.createElement("span");
  badge.className = `badge severity-${severityClass(severity)}`;
  badge.textContent = severityLabel(severity);
  return badge;
}

function severityLabel(severity) {
  const value = String(severity || "").trim();
  if (!value) return "Unknown";
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
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function formatTime(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) return String(seconds);
  return date.toLocaleString();
}

document.getElementById("refresh").addEventListener("click", render);
render();
