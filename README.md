# Autonomous AI Immune System

An AI-powered security system that mimics the human immune system. It monitors web apps, databases, and server infrastructure for threats, then deploys specialized AI agents to contain, repair, and learn from each attack — getting smarter with every incident.

## How It Works

Just like the human immune system:

| Biology | This System |
|---|---|
| Pathogen detected | Threat event detected by sensors |
| Innate immune response (fast) | Sentinel Agent — blocks IP, rate-limits instantly |
| Adaptive response (T-cells) | Investigator Agent — LLM-powered deep threat analysis |
| Tissue repair | Healer Agent — restores configs, patches vulnerabilities |
| NK cells hunting | Hunter Agent — scans for related indicators of compromise |
| B-cells / antibodies | Memory Agent — writes new attack signatures to DB |
| Immunological memory | Memory Store — future attacks handled faster |

## Architecture

```
Sensors → Detector → Orchestrator (LangGraph) → Agents → Memory
                           ↑                               |
                           └───────────────────────────────┘
                                  (feedback loop)
```

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### 3. Start Redis (required for event streaming)

```bash
# Using Docker
docker run -d -p 6379:6379 redis:7-alpine

# Or use Docker Compose for everything
docker-compose up -d redis
```

### 4. Run the simulation target (the "body" being protected)

```bash
uvicorn simulation.target_env:app --port 8001 --reload
```

### 5. Run the immune system API

```bash
uvicorn api.main:app --port 8000 --reload
```

### 6. Start the orchestrator (deploys agents on threat detection)

```bash
python -m core.orchestrator
```

### 7. Launch the dashboard

```bash
streamlit run dashboard/app.py
```

### 8. Fire simulated attacks

```bash
python -m simulation.attack_simulator
```

## Components

### Sensors (`core/sensors/`)
- **log_sensor.py** — Monitors log files for suspicious patterns
- **network_sensor.py** — Tracks connection rates, port scans
- **db_sensor.py** — Watches for SQL injection, unusual query patterns

### Detector (`core/detector/`)
- **anomaly.py** — Z-score based anomaly detection; trains over time
- **signatures.py** — Pattern matching against known attack signatures in memory

### Agents (`agents/`)
- **sentinel.py** — Instant containment: block IPs, kill processes, rate-limit
- **investigator.py** — LLM analysis: classifies attack type, severity, recommends actions
- **healer.py** — LLM repair: restores files, reverts changes, patches endpoints
- **hunter.py** — Active hunting: finds related IOCs across the system
- **memory_agent.py** — Learning: writes signatures and playbooks, lowers future thresholds

### Memory (`memory/`)
- **models.py** — SQLAlchemy ORM for threat events, signatures, playbooks
- **store.py** — Read/write interface for the memory database
- **immunization.py** — Generates adaptive security rules from past attacks

### Simulation (`simulation/`)
- **target_env.py** — Intentionally vulnerable FastAPI app (the "body")
- **attack_simulator.py** — Fires 5 attack types: SQL injection, brute force, port scan, file injection, DDoS

### API (`api/main.py`)
FastAPI backend with endpoints:
- `GET /status` — System health
- `GET /threats` — Recent threat events
- `GET /agents/active` — Currently running agents
- `GET /memory/signatures` — Known attack signatures
- `GET /memory/playbooks` — Response playbooks

### Dashboard (`dashboard/app.py`)
Real-time Streamlit dashboard showing:
- Live threat feed
- Agent activity log
- Immunological memory growth
- System health metrics

## Environment Variables

See `.env.example` for all configuration options.

Key settings:
- `OPENAI_API_KEY` — Required for LLM agents
- `SIMULATE_ACTIONS` — Set to `false` to execute real OS-level responses
- `ANOMALY_THRESHOLD` — Z-score sensitivity for anomaly detection

## Attack Types Simulated

1. **SQL Injection** — Malicious SQL payloads in login forms
2. **Brute Force** — Rapid repeated authentication attempts
3. **Port Scan** — Fast enumeration of many endpoints
4. **File Injection** — Malicious file uploads with dangerous content
5. **DDoS** — High-volume request flooding
