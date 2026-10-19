# Network Intrusion Detection and Threat Monitoring System

A beginner-friendly Computer Networks mini-project. It monitors network
traffic, detects predefined suspicious patterns, stores the resulting security
events in SQLite, and displays them on a minimal, auto-refreshing web
dashboard.

> ⚠️ **Responsible use.** Detections produced by this tool are *possible*
> suspicious activity, **not proof of an attack**. Only monitor networks you
> own or are explicitly authorized to monitor. Never generate attack traffic
> or scan external networks.

---

## Table of contents

- [Features](#features)
- [Quickstart](#quickstart)
- [How it works](#how-it-works)
- [Detection modules](#detection-modules)
- [Running it](#running-it)
- [Using the dashboard](#using-the-dashboard)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Testing](#testing)
- [Project structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Notes, limitations & safety](#notes-limitations--safety)
- [Tech stack](#tech-stack)

---

## Features

- **Five detection rules** — port scanning, traffic-rate anomalies, ARP
  spoofing, unknown devices, and repeated connection attempts.
- **Live, real-time dashboard** — a clean HTML/CSS/JS page that auto-refreshes
  every 10 seconds and shows alerts, tracked devices, and summary stats.
- **Two live modes** — a privilege-free synthetic demo feed (`--live-demo`) and
  real packet capture (`--capture`).
- **Read-only JSON API** — simple endpoints you can query with `curl` or build
  on.
- **Deduplication** — one continuing event does not spam the alert list.
- **Config-driven** — every threshold lives in `config.json`; nothing is
  hardcoded across the codebase.
- **Fully tested** — 156 deterministic tests built from synthetic packets; no
  privileges or real traffic required.
- **Safe by default** — binds to `127.0.0.1` only, and starts no data source
  unless you explicitly ask it to.

---

## Quickstart

```bash
# 1. Clone and enter the project
git clone https://github.com/<your-username>/Network-Intrusion-Detection.git
cd Network-Intrusion-Detection

# 2. Create a virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 3. Run it with the live demo feed (recommended — no admin rights needed)
python run.py --live-demo
```

Then open **<http://127.0.0.1:5000/>** in your browser and watch alerts appear
within a few seconds. Press `Ctrl+C` to stop.

> **Python version.** The project targets **Python 3.12** but also runs on
> newer versions (tested on 3.14). On macOS you can install 3.12 with
> `brew install python@3.12` and use `python3.12 -m venv .venv`, or just use
> your system `python3`.

---

## How it works

Data flows one way, through small, single-purpose modules:

```
packet source → parser → engine (5 detectors + dedup) → SQLite → JSON API → dashboard
```

- **Packet source** is either real traffic (Scapy capture) or synthetic
  records generated for demos and tests.
- The **engine** runs every record through all detectors, drops duplicate
  alerts, and stores survivors in SQLite.
- The **API** and **dashboard** are strictly read-only: they display stored
  data and never trigger detection or capture.

---

## Detection modules

| # | Rule | What it flags |
| - | --- | --- |
| 1 | **Port scanning** | Many unique destination ports from one source within a time window. |
| 2 | **Traffic anomaly** | Packet rate above a configured threshold. |
| 3 | **ARP anomaly** | An observed IPv4-to-MAC mapping changes unexpectedly (possible ARP spoofing). |
| 4 | **Unknown device** | A device not present in the configured known-device inventory. |
| 5 | **Repeated connections** | Repeated TCP attempts to the same service above a threshold. |

Each rule lives in its own file under `nids/detectors/`, so adding a new one is
self-contained. All detections are *possible* suspicious activity, never proof
of an attack.

---

## Running it

All commands bind the server to `127.0.0.1` only. Run them from the project
root with the virtual environment active (or prefix with `.venv/bin/python`).

### 1. Dashboard only (default)

```bash
python run.py
```

Serves the dashboard against whatever is already in `nids.db` (initially
empty). Starts no data source. The first run creates `nids.db` in the project
root.

### 2. Live demo feed — recommended

```bash
python run.py --live-demo
```

Drives the **real** detection engine with synthetic traffic (port scans,
bursts, ARP changes, unknown devices, repeated connections) on a timer, so
alerts and devices appear on the dashboard within seconds. Needs **no
administrator rights** and generates **no real network traffic** — ideal for
demos and presentations.

### 3. Real packet capture

```bash
sudo python run.py --capture
```

Sniffs real packets through `nids/capture.py`. On macOS this usually requires
root access to `/dev/bpf*` (hence `sudo`). On a normal setup (no monitor mode)
you will mostly see traffic to and from your own machine, so real alerts may be
sparse.

### Options

| Flag | Description |
| --- | --- |
| `--live-demo` | Start the synthetic live feed (no privileges). |
| `--capture` | Start real packet capture (needs root on macOS). |
| `--interface <name>` | Network interface to capture on (with `--capture`). |
| `--db <path>` | Use a different SQLite file instead of `nids.db`. |

The flags can be combined. There is also a standalone one-shot demo that writes
a batch of alerts to `demo.db` and prints how to view them:

```bash
python demo.py
```

---

## Using the dashboard

Open <http://127.0.0.1:5000/>. You will see:

- **Summary cards** — total alerts, tracked devices, and a breakdown by
  severity (high / medium / low).
- **Recent alerts** — newest first, with time, severity, type, source and
  destination IPs, and a description.
- **Tracked devices** — IP, MAC, hostname, label, whether the device is known,
  and when it was last seen.

The page refreshes automatically every 10 seconds; the **Refresh** button
forces an immediate update, and a status pill shows whether the last fetch
succeeded.

---

## API reference

All endpoints are read-only and return JSON.

| Endpoint | Response |
| --- | --- |
| `GET /api/health` | `{"status": "ok"}` |
| `GET /api/alerts` | `{"count": N, "alerts": [<alert>, ...]}` (newest first) |
| `GET /api/devices` | `{"count": N, "devices": [<device>, ...]}` |
| `GET /api/stats` | `{"total_alerts": N, "alerts_by_severity": {...}, "tracked_devices": N}` |
| `GET /api/traffic` | `{"window_seconds", "generated_at", "summary", "series", "protocols", "top_talkers"}` |

`GET /api/alerts` accepts an optional `limit` query parameter (whole number,
1–500; default 50). Invalid limits return `400` with `{"error": "..."}`.
Unknown routes return a JSON `404`, and unexpected failures return a generic
JSON `500` without stack traces.

`GET /api/traffic` accepts an optional `window` query parameter (whole number
of seconds, 1 to `traffic_monitor.max_window_seconds`; default
`traffic_monitor.default_window_seconds`). It summarizes the traffic seen over
that window: `series` is per-second `{bucket, packets, bytes}`, `protocols` is
per-protocol totals, `top_talkers` is the busiest source IPs, and `summary`
holds totals plus peak/average packets- and bytes-per-second.

- **Alert** object: `alert_type`, `severity`, `message`, `timestamp` (Unix
  epoch seconds), `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`.
- **Device** object: `ip`, `mac`, `hostname`, `label`, `known`, `first_seen`,
  `last_seen`.

Example:

```bash
curl -s http://127.0.0.1:5000/api/stats
curl -s "http://127.0.0.1:5000/api/alerts?limit=5"
curl -s "http://127.0.0.1:5000/api/traffic?window=60"
```

### Live traffic portal

Open <http://127.0.0.1:5000/live> (linked from the top of the alerts
dashboard) for real-time **network monitoring and traffic analysis**: current
and peak throughput, a bandwidth-over-time chart, the protocol mix, and the top
talkers. It auto-refreshes every 2 seconds and is populated by whichever live
source is running (`--live-demo` or `--capture`). Like the rest of the app it
is read-only and bound to `127.0.0.1`.

---

## Configuration

All thresholds live in `config.json`; never hardcode thresholds elsewhere.

| Section | Keys |
| --- | --- |
| `capture` | `enabled`, `interface`, `packet_limit`, `timeout_seconds` (disabled by default) |
| `port_scan` | `enabled`, `window_seconds`, `unique_ports_threshold` |
| `traffic_anomaly` | `enabled`, `window_seconds`, `packet_rate_threshold` |
| `arp_anomaly` | `enabled` |
| `unknown_device` | `enabled` (uses the `known_devices` inventory) |
| `repeated_connections` | `enabled`, `window_seconds`, `attempts_threshold` |
| `dedup` | `window_seconds` (how long an ongoing event stays quiet) |
| `traffic_monitor` | `enabled`, `retention_seconds`, `default_window_seconds`, `max_window_seconds`, `top_talkers` |
| `known_devices` | list of `{"ip": "...", "mac": "...", "label": "..."}` (mac & label optional) |

Missing sections fall back to defaults in `nids/config.py`; invalid files or
values raise a clear `ConfigError`.

---

## Testing

Run the full suite (uses temporary SQLite files; never touches the real
`nids.db` and never captures packets):

```bash
.venv/bin/python -m pytest -q
```

All tests build the pipeline from synthetic packet records
(`nids/synthetic.py`), so they are deterministic and need no privileges.

---

## Project structure

```
run.py                 entry point (dashboard + API; --live-demo / --capture opt in)
demo.py                one-shot CLI demo of all five detectors
config.json            all thresholds and the known-device inventory
nids/config.py         load/validate config, apply defaults
nids/models.py         PacketRecord / Alert / Device dataclasses
nids/parser.py         Scapy packet -> PacketRecord (fills length in bytes)
nids/synthetic.py      fake PacketRecords for tests/demo
nids/livefeed.py       background synthetic feed for --live-demo
nids/detectors/        one file per detection rule
nids/dedup.py          suppress duplicate ongoing alerts
nids/engine.py         run detectors over records, collect alerts, meter traffic
nids/metrics.py        TrafficMeter: aggregate records into per-second buckets
nids/db.py             SQLite schema + read/write helpers (alerts, devices, traffic)
nids/capture.py        Scapy sniff() wrapper (only place using live capture)
nids/api.py            read-only Flask JSON API (create_app)
nids/web/              dashboard + live portal blueprint, templates, static assets
tests/                 pytest tests
```

---

## Troubleshooting

- **Port 5000 already in use** — macOS AirPlay Receiver uses port 5000. Turn it
  off in *System Settings → General → AirDrop & Handoff*, or edit `PORT` in
  `run.py`.
- **`--capture` sees nothing / permission denied** — real capture needs root
  (`sudo python run.py --capture`) and, on normal macOS, only sees your own
  machine's traffic. Use `--live-demo` for a reliable demo.
- **`ModuleNotFoundError`** — activate the virtual environment
  (`source .venv/bin/activate`) and reinstall requirements.
- **Dashboard shows "Could not load data"** — the server isn't running or
  crashed; restart `python run.py`.

---

## Notes, limitations & safety

- Detections are *possible* suspicious activity, **never proof of an attack**.
- The dashboard binds to `127.0.0.1` only and must never be exposed publicly.
- No authentication is implemented; run it locally only.
- The API is read-only; it has no endpoints that start/stop capture or write
  data.
- The dashboard shows the most recent alerts and auto-refreshes every 10
  seconds; there is no pagination or filtering yet.

---

## Tech stack

- **Python** (target 3.12; runs on newer versions)
- **Scapy** — packet capture and parsing
- **Flask** — backend and dashboard serving
- **SQLite** (standard-library `sqlite3`) — persistence
- **Plain HTML, minimal CSS, vanilla JavaScript** — frontend (no frameworks)
