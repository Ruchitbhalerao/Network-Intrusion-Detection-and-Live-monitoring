const REFRESH_MS = 2000;
const SVG_NS = "http://www.w3.org/2000/svg";
const CHART_WIDTH = 640;
const CHART_HEIGHT = 220;
const CHART_PADDING = 8;

let refreshing = false;
let hasLoaded = false;
let timer = null;

const statusEl = document.getElementById("status");
const lastUpdatedEl = document.getElementById("last-updated");
const refreshButton = document.getElementById("refresh");
const windowSelect = document.getElementById("window");

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

function selectedWindow() {
  const value = parseInt(windowSelect.value, 10);
  return Number.isNaN(value) ? 60 : value;
}

async function loadPortal() {
  if (refreshing) {
    return;
  }
  refreshing = true;
  refreshButton.disabled = true;
  setStatus("Loading…", "loading");

  try {
    const health = await fetchJSON("/api/health");
    if (!health || health.status !== "ok") {
      throw new Error("the API reported an unhealthy status");
    }

    const traffic = await fetchJSON(`/api/traffic?window=${selectedWindow()}`);
    renderSummary(traffic.summary || {});
    renderChart(traffic);
    renderProtocols(Array.isArray(traffic.protocols) ? traffic.protocols : []);
    renderTalkers(Array.isArray(traffic.top_talkers) ? traffic.top_talkers : []);

    hasLoaded = true;
    setStatus("Live", "ok");
    lastUpdatedEl.textContent = `Updated ${new Date().toLocaleTimeString()}`;
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

function renderSummary(summary) {
  document.getElementById("current-rate").textContent = formatRate(
    summary.avg_bytes_per_second
  );
  document.getElementById("current-pps").textContent = `${formatNumber(
    summary.avg_packets_per_second,
    1
  )} pkt/s avg`;

  document.getElementById("peak-rate").textContent = formatRate(
    summary.peak_bytes_per_second
  );
  document.getElementById("peak-pps").textContent = `${formatNumber(
    summary.peak_packets_per_second
  )} pkt/s peak`;

  document.getElementById("total-bytes").textContent = formatBytes(
    summary.total_bytes
  );
  document.getElementById("total-packets").textContent = `${formatNumber(
    summary.total_packets
  )} packets`;

  document.getElementById("protocol-count").textContent = display(summary.protocols);
  document.getElementById("active-seconds").textContent = `${formatNumber(
    summary.active_seconds
  )} s with traffic`;
}

function renderChart(traffic) {
  const chart = document.getElementById("bandwidth-chart");
  const emptyNote = document.getElementById("chart-empty");
  const series = Array.isArray(traffic.series) ? traffic.series : [];

  chart.replaceChildren();

  if (series.length === 0) {
    chart.style.display = "none";
    emptyNote.style.display = "block";
    return;
  }
  chart.style.display = "block";
  emptyNote.style.display = "none";

  const values = densify(series, traffic.generated_at, traffic.window_seconds);
  const max = Math.max(...values, 1);
  const innerWidth = CHART_WIDTH - CHART_PADDING * 2;
  const innerHeight = CHART_HEIGHT - CHART_PADDING * 2;
  const step = values.length > 1 ? innerWidth / (values.length - 1) : 0;

  const points = values.map((value, index) => {
    const x = CHART_PADDING + index * step;
    const y = CHART_PADDING + innerHeight - (value / max) * innerHeight;
    return [x, y];
  });

  const baseline = CHART_PADDING + innerHeight;
  const areaPath =
    `M ${points[0][0]} ${baseline} ` +
    points.map(([x, y]) => `L ${x} ${y}`).join(" ") +
    ` L ${points[points.length - 1][0]} ${baseline} Z`;
  const linePath = `M ${points.map(([x, y]) => `${x} ${y}`).join(" L ")}`;

  chart.appendChild(svgEl("path", { d: areaPath, class: "chart-area" }));
  chart.appendChild(svgEl("path", { d: linePath, class: "chart-line" }));
}

function densify(series, generatedAt, windowSeconds) {
  const byBucket = new Map();
  for (const point of series) {
    byBucket.set(point.bucket, point.bytes || 0);
  }
  const end = Math.floor(generatedAt || Date.now() / 1000);
  const span = windowSeconds || 60;
  const values = [];
  for (let second = end - span + 1; second <= end; second += 1) {
    values.push(byBucket.get(second) || 0);
  }
  return values;
}

function renderProtocols(protocols) {
  const list = document.getElementById("protocol-bars");
  list.replaceChildren();

  if (protocols.length === 0) {
    list.appendChild(listItem("No traffic yet", "muted"));
    return;
  }

  const max = Math.max(...protocols.map((item) => item.bytes || 0), 1);

  for (const item of protocols) {
    const row = document.createElement("li");
    row.className = "bar-row";

    const label = document.createElement("span");
    label.className = "bar-label";
    label.textContent = display(item.protocol);

    const track = document.createElement("span");
    track.className = "bar-track";
    const fill = document.createElement("span");
    fill.className = "bar-fill";
    fill.style.width = `${Math.round(((item.bytes || 0) / max) * 100)}%`;
    track.appendChild(fill);

    const value = document.createElement("span");
    value.className = "bar-value";
    value.textContent = `${formatBytes(item.bytes)} / ${formatNumber(item.packets)} pkt`;

    row.append(label, track, value);
    list.appendChild(row);
  }
}

function renderTalkers(talkers) {
  const body = document.getElementById("talkers-body");
  body.replaceChildren();

  if (talkers.length === 0) {
    body.appendChild(emptyRow(4, "No traffic recorded yet."));
    return;
  }

  const total = talkers.reduce((sum, item) => sum + (item.bytes || 0), 0) || 1;

  for (const talker of talkers) {
    const row = document.createElement("tr");
    row.appendChild(cell(display(talker.src_ip)));
    row.appendChild(cell(formatNumber(talker.packets)));
    row.appendChild(cell(formatBytes(talker.bytes)));
    row.appendChild(cell(`${Math.round(((talker.bytes || 0) / total) * 100)}%`));
    body.appendChild(row);
  }
}

function renderUnavailable() {
  for (const id of ["current-rate", "peak-rate", "total-bytes", "protocol-count"]) {
    document.getElementById(id).textContent = "—";
  }
  for (const id of ["current-pps", "peak-pps", "total-packets", "active-seconds"]) {
    document.getElementById(id).textContent = "—";
  }
  document.getElementById("bandwidth-chart").style.display = "none";
  document.getElementById("chart-empty").style.display = "block";
  document.getElementById("chart-empty").textContent = "Traffic data unavailable.";
  document
    .getElementById("protocol-bars")
    .replaceChildren(listItem("Unavailable", "muted"));
  document
    .getElementById("talkers-body")
    .replaceChildren(emptyRow(4, "Traffic data unavailable."));
}

function svgEl(name, attributes) {
  const element = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attributes)) {
    element.setAttribute(key, value);
  }
  return element;
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
    return "—";
  }
  return String(value);
}

function formatNumber(value, decimals = 0) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return "—";
  }
  return Number(value).toLocaleString(undefined, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes)) {
    return "—";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  const decimals = unit === 0 ? 0 : 1;
  return `${size.toFixed(decimals)} ${units[unit]}`;
}

function formatRate(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes)) {
    return "—";
  }
  return `${formatBytes(bytes)}/s`;
}

function setStatus(message, kind) {
  statusEl.textContent = message;
  statusEl.className = `status status-${kind}`;
}

function restartTimer() {
  if (timer !== null) {
    clearInterval(timer);
  }
  timer = setInterval(loadPortal, REFRESH_MS);
}

refreshButton.addEventListener("click", loadPortal);
windowSelect.addEventListener("change", () => {
  loadPortal();
  restartTimer();
});

loadPortal();
restartTimer();
