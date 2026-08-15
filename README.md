# AI-Assisted Intrusion Detection System

A learning project: build up a real IDS pipeline (Suricata) and progressively
bolt AI onto it, one capability at a time, to understand both how IDS tooling
works and how to integrate LLMs into a security workflow.

## Roadmap

- [x] **Phase 0 — Suricata pipeline.** Suricata running in Docker against a
      sample pcap, producing `eve.json`/`fast.log`/`stats.log` in `logs/`.
- [x] **Phase 1 — Alert triage & explanation** (`analyzer/`). Feed Suricata's
      alerts to Gemini, get a plain-English explanation + severity + next
      step, browse them in a small dashboard a non-technical person could use.
- [ ] **Phase 2 — Anomaly detection.** Engineer features from flow data and
      train a classifier to catch what signature-based rules miss.
- [ ] **Phase 3 — RAG over logs/rules.** Natural-language Q&A over historical
      alerts and the rule set ("what happened with this IP last week?").

## How the pieces fit together

```
pcaps/test1.pcap
      │
      ▼
  Suricata (Docker, rules/suricata.rules)
      │
      ▼
  logs/eve.json  ──────────────┐   (every event: alerts, dns, http, tls, flow…)
      │                        │
      ▼                        │
  analyzer/ingest.py           │
  groups repeated alerts by    │
  (signature, src, dest)       │
      │                        │
      ▼                        │
  analyzer/explain.py  ────────┘
  one Gemini call per group,
  structured output (severity,
  plain-English summary, next step)
      │
      ▼
  analyzer/alerts.db (SQLite)
      │
      ▼
  analyzer/app.py (Flask dashboard)
```

## Why grouping alerts before calling the LLM

Suricata fires one alert *per matching packet*. In the sample pcap, 561 raw
alert events collapse into just 14 distinct (signature, source, destination)
groups — one NetSupport RAT check-in pattern alone accounts for 264 of them.
Explaining each raw event would be slow, expensive, and mostly redundant, so
`ingest.py` aggregates first. This mirrors what real SOC tooling does and is
also the cheapest way to keep the demo's API usage small.

## Setup

### 1. Suricata (already wired up)

```bash
docker build -t suricata-ids .
docker run --rm -v $(pwd)/pcaps:/pcaps -v $(pwd)/logs:/var/log/suricata -v $(pwd)/rules:/etc/suricata/rules \
  suricata-ids suricata -r /pcaps/test1.pcap -l /var/log/suricata -S /etc/suricata/rules/suricata.rules
```

This produces/refreshes `logs/eve.json`, which is what `analyzer/` reads.

### 2. The analyzer (Phase 1)

```bash
cd analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env and set GEMINI_API_KEY (get one at https://aistudio.google.com/apikey)
```

Run the enrichment pipeline (reads `logs/eve.json`, writes `analyzer/alerts.db`):

```bash
python cli.py
```

It prints progress per alert group and skips groups it has already
explained, so it's safe to re-run after Suricata produces new alerts.

Then start the dashboard:

```bash
python app.py
# open http://127.0.0.1:5050
```

## What to poke at, if you want to learn from this code

- `analyzer/ingest.py` — the alert-grouping logic and a simple example of
  extracting hostnames from DNS answers for context.
- `analyzer/explain.py` — uses Gemini's [structured outputs](https://ai.google.dev/gemini-api/docs/structured-output)
  (`response_schema`) with a Pydantic schema, so the response is always
  valid JSON with the fields you defined — no regex-scraping the model's prose.
- `analyzer/db.py` — deliberately the simplest possible SQLite schema (one
  table). Good place to look if you want to add fields like MITRE ATT&CK
  technique mapping later.
- `GEMINI_EFFORT` in `.env` — controls how much the model "thinks" before
  answering (`low`/`medium`/`high`, mapped to a thinking-token budget in
  `explain.py`). Worth experimenting with to see the cost/quality/latency
  tradeoff on this kind of classification task.

## Cost note

Each new alert group costs one Gemini API call (~1-2K input tokens, capped at
1024 output tokens). On the sample pcap that's 14 calls total, once — after
that, `cli.py` only calls the API for groups it hasn't seen before.
