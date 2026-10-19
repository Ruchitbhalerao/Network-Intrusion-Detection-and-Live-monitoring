# AGENTS.md

Guidance for AI/agent sessions working in this repository. Keep it up to date.

## Project

Network Intrusion Detection and Threat Monitoring System — a beginner-friendly
Computer Networks mini-project. It monitors network traffic, detects predefined
suspicious patterns, stores security events in SQLite, and shows them on a
minimal web dashboard. It also measures live traffic (packets, bytes, and
protocol usage) and presents it on a real-time traffic portal at ``/live``.

## Tech stack (do not add more without approval)

- Python (target interpreter: **3.12**, run inside a project-local `.venv`)
- Scapy — packet capture and parsing (used only in the capture/parser layer)
- Flask — backend and serving the dashboard
- SQLite (via the standard-library `sqlite3` module) — persistence
- Plain HTML, minimal CSS, vanilla JavaScript — frontend

No React, Vue, Tailwind, ORMs, animation or CSS frameworks.

## Detection modules

1. Possible port scanning — many unique destination ports from one source in a time window.
2. Traffic anomaly — packet rate above a configured threshold.
3. ARP anomaly — an observed IPv4-to-MAC mapping changes unexpectedly.
4. Unknown device — a device not present in the configured inventory.
5. Repeated connection attempts — repeated TCP attempts to the same service above a threshold.

## Development rules

- Build incrementally, one stage at a time. Do not implement the whole app at once.
- Keep the architecture modular but simple enough for a student to follow.
- Separate concerns: parsing, detection rules, database operations, Flask routes.
- All thresholds live in `config.json`; never hardcode them across the codebase.
- Avoid duplicate alerts for the same continuing event (dedup layer).
- Develop and test with synthetic packet records before enabling live capture.
- Never generate attack traffic or scan external networks. Only monitor traffic
  you own or are explicitly authorized to monitor.
- Treat detections as *possible* suspicious activity, never as proof of an attack.
- Do not expose the dashboard publicly. Flask must bind to `127.0.0.1` only.
- Never claim a check/test passed unless it was actually run and the result observed.

## Layout

```
run.py                 entry point (dashboard + JSON API; --live-demo / --capture opt in)
config.json            all thresholds and the known-device inventory
nids/config.py         load/validate config, apply defaults
nids/models.py         PacketRecord / Alert / Device dataclasses
nids/parser.py         Scapy packet -> PacketRecord (fills length in bytes)
nids/synthetic.py      fake PacketRecords for tests/demo
nids/livefeed.py       background synthetic feed for --live-demo
nids/engine.py         run detectors over records, collect alerts, meter traffic
nids/metrics.py        TrafficMeter: aggregate records into per-second buckets
nids/dedup.py          suppress duplicate ongoing alerts
nids/capture.py        Scapy sniff() wrapper (only place using live capture)
nids/db.py             SQLite schema + read/write helpers (alerts, devices, traffic)
nids/api.py            read-only Flask JSON API (create_app)
nids/detectors/        one file per detection rule
nids/web/              dashboard + live portal blueprint, templates, static
tests/                 pytest tests
```

## Traffic portal

Every record that reaches `engine.process_record()` is also counted by a
`TrafficMeter` (`nids/metrics.py`), which groups packets into one-second
buckets per protocol and per source IP and flushes completed seconds to the
`traffic` and `talkers` tables. The `/api/traffic?window=<seconds>` endpoint
reads those tables (series, protocol breakdown, top talkers, summary) and the
`/live` page polls it every 2s to draw bandwidth, protocol mix, and top
talkers with vanilla JS + inline SVG (no chart library). Retention and the
default/max window live under `traffic_monitor` in `config.json`.

## Commands

```bash
source .venv/bin/activate          # activate the local environment
.venv/bin/python run.py            # start the dashboard + API on 127.0.0.1:5000
pytest -q                          # run all tests
pytest tests/test_smoke.py -q      # run a single test file
```

## Conventions

- Do not add code comments unless explicitly requested.
- Keep functions small and single-purpose.
- Prefer the standard library over new dependencies.
