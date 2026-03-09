"""
Immune System API — FastAPI backend.
Exposes system status, threat history, active agents, and memory.
"""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from config.settings import settings
from config.logging_config import setup_logging
from memory import store
from core.orchestrator import get_active_responses, process_threat, run_orchestrator

logger = setup_logging("api")
_orchestrator_task: Optional[asyncio.Task] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _orchestrator_task
    await store.init_db()
    logger.info("[API] Database initialized")
    _orchestrator_task = asyncio.create_task(run_orchestrator())
    logger.info("[API] Orchestrator started")
    yield
    if _orchestrator_task:
        _orchestrator_task.cancel()
        try:
            await _orchestrator_task
        except asyncio.CancelledError:
            pass
    logger.info("[API] Shutdown complete")


app = FastAPI(
    title="Autonomous AI Immune System",
    description="Security monitoring and autonomous response API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# Request models
# ─────────────────────────────────────────────

class ManualThreatRequest(BaseModel):
    event_type: str
    source_ip: Optional[str] = "192.168.1.1"
    target_endpoint: Optional[str] = "/test"
    severity: Optional[str] = "medium"
    payload_sample: Optional[str] = ""


# ─────────────────────────────────────────────
# Core endpoints
# ─────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "system": "Autonomous AI Immune System",
        "version": "1.0.0",
        "status": "active",
        "timestamp": datetime.utcnow().isoformat(),
        "dashboard": "http://localhost:8000/dashboard",
    }


@app.get("/status")
async def get_status():
    stats = await store.get_memory_stats()
    active = get_active_responses()
    in_progress = sum(1 for r in active.values() if r.get("status") == "processing")
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "orchestrator_running": _orchestrator_task is not None and not _orchestrator_task.done(),
        "active_responses": in_progress,
        "simulate_actions": settings.simulate_actions,
        "llm_enabled": bool(settings.openai_api_key),
        **stats,
    }


@app.get("/threats")
async def get_threats(limit: int = 50):
    threats = await store.get_recent_threats(limit=limit)
    return {"threats": threats, "total": len(threats)}


@app.get("/threats/{threat_id}")
async def get_threat(threat_id: int):
    threat = await store.get_threat_by_id(threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat


@app.get("/agents/active")
async def get_active_agents():
    responses = get_active_responses()
    return {"active_responses": list(responses.values()), "count": len(responses)}


@app.get("/memory/signatures")
async def get_signatures():
    sigs = await store.get_all_active_signatures()
    return {"signatures": sigs, "total": len(sigs)}


@app.get("/memory/playbooks")
async def get_playbooks():
    playbooks = await store.get_all_playbooks()
    return {"playbooks": playbooks, "total": len(playbooks)}


@app.get("/memory/rules")
async def get_adaptive_rules():
    rules = await store.get_active_rules()
    return {"rules": rules, "total": len(rules)}


@app.get("/memory/stats")
async def get_memory_stats():
    return await store.get_memory_stats()


@app.post("/threats/inject")
async def inject_threat(req: ManualThreatRequest, background_tasks: BackgroundTasks):
    event = {
        "source": "manual_injection",
        "event_type": req.event_type,
        "source_ip": req.source_ip,
        "target_endpoint": req.target_endpoint,
        "severity": req.severity,
        "payload_sample": req.payload_sample,
        "confidence": 0.8,
        "timestamp": datetime.utcnow().isoformat(),
        "raw_data": {},
    }
    background_tasks.add_task(process_threat, event)
    return {"status": "dispatched", "message": f"Immune response triggered for {req.event_type}", "event": event}


# ─────────────────────────────────────────────
# Built-in HTML Dashboard
# ─────────────────────────────────────────────

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(content=_build_dashboard_html())


def _build_dashboard_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Immune System Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0a0e1a; color: #cdd6f4; font-family: 'Segoe UI', system-ui, sans-serif; }
  header { background: linear-gradient(135deg, #1a1f35, #0d1124); padding: 24px 32px; border-bottom: 1px solid #2a3050; }
  header h1 { font-size: 1.8rem; color: #4facfe; }
  header p { color: #8892b0; margin-top: 4px; }
  .container { max-width: 1400px; margin: 0 auto; padding: 24px 32px; }
  .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .metric { background: #1a1f35; border: 1px solid #2a3050; border-radius: 12px; padding: 20px; text-align: center; }
  .metric .value { font-size: 2rem; font-weight: bold; color: #4facfe; }
  .metric .label { font-size: 0.8rem; color: #8892b0; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 32px; }
  .card { background: #1a1f35; border: 1px solid #2a3050; border-radius: 12px; padding: 24px; }
  .card h2 { font-size: 1rem; color: #8892b0; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }
  .threat-row { display: flex; align-items: center; gap: 12px; padding: 10px 0; border-bottom: 1px solid #2a3050; }
  .threat-row:last-child { border-bottom: none; }
  .badge { padding: 2px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; }
  .critical { background: #3d1020; color: #ff2d55; }
  .high { background: #2d1a0e; color: #ff6b35; }
  .medium { background: #2d2a0e; color: #ffd60a; }
  .low { background: #0e2d1a; color: #30d158; }
  .status-resolved { color: #30d158; }
  .status-detected { color: #ffd60a; }
  .status-error { color: #ff2d55; }
  .sig-row { padding: 8px 0; border-bottom: 1px solid #2a3050; font-size: 0.85rem; }
  .sig-row:last-child { border-bottom: none; }
  .sig-type { color: #4facfe; font-weight: bold; }
  .sig-hits { color: #ffd60a; font-size: 0.75rem; }
  .sig-threshold { color: #8892b0; font-size: 0.75rem; }
  .inject-form { background: #1a1f35; border: 1px solid #2a3050; border-radius: 12px; padding: 24px; margin-bottom: 32px; }
  .inject-form h2 { font-size: 1rem; color: #8892b0; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }
  .form-row { display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end; }
  select, input { background: #0d1124; border: 1px solid #2a3050; color: #cdd6f4; padding: 8px 12px; border-radius: 8px; font-size: 0.9rem; }
  button { background: #4facfe; color: #0a0e1a; border: none; padding: 8px 20px; border-radius: 8px; font-weight: bold; cursor: pointer; font-size: 0.9rem; }
  button:hover { background: #6dbeff; }
  .refresh-btn { background: #2a3050; color: #8892b0; }
  .toast { position: fixed; top: 20px; right: 20px; background: #30d158; color: #0a0e1a; padding: 12px 20px; border-radius: 8px; font-weight: bold; display: none; z-index: 999; }
  .empty { color: #4a5568; font-style: italic; padding: 8px 0; }
</style>
</head>
<body>
<header>
  <h1>🧬 Autonomous AI Immune System</h1>
  <p>Real-time threat detection, autonomous response, and immunological learning</p>
</header>

<div class="container">

  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px;">
    <div id="last-updated" style="color:#8892b0; font-size:0.85rem;"></div>
    <button class="refresh-btn" onclick="loadAll()">↻ Refresh</button>
  </div>

  <!-- Metrics -->
  <div class="metrics" id="metrics">
    <div class="metric"><div class="value" id="m-total">—</div><div class="label">Threats Seen</div></div>
    <div class="metric"><div class="value" id="m-resolved">—</div><div class="label">Resolved</div></div>
    <div class="metric"><div class="value" id="m-sigs">—</div><div class="label">Known Signatures</div></div>
    <div class="metric"><div class="value" id="m-playbooks">—</div><div class="label">Playbooks</div></div>
    <div class="metric"><div class="value" id="m-rules">—</div><div class="label">Adaptive Rules</div></div>
    <div class="metric"><div class="value" id="m-active">—</div><div class="label">Active Responses</div></div>
  </div>

  <!-- Inject Threat Form -->
  <div class="inject-form">
    <h2>🚨 Inject Test Threat</h2>
    <div class="form-row">
      <div>
        <label style="display:block;font-size:0.8rem;color:#8892b0;margin-bottom:4px;">Attack Type</label>
        <select id="f-type">
          <option value="sql_injection">SQL Injection</option>
          <option value="brute_force">Brute Force</option>
          <option value="port_scan">Port Scan</option>
          <option value="file_injection">File Injection</option>
          <option value="ddos">DDoS</option>
        </select>
      </div>
      <div>
        <label style="display:block;font-size:0.8rem;color:#8892b0;margin-bottom:4px;">Source IP</label>
        <input id="f-ip" value="10.0.1.99" style="width:140px;">
      </div>
      <div>
        <label style="display:block;font-size:0.8rem;color:#8892b0;margin-bottom:4px;">Severity</label>
        <select id="f-severity">
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high" selected>High</option>
          <option value="critical">Critical</option>
        </select>
      </div>
      <button onclick="injectThreat()">Inject Threat</button>
    </div>
  </div>

  <!-- Threat Feed + Memory -->
  <div class="grid-2">
    <div class="card">
      <h2>⚡ Live Threat Feed</h2>
      <div id="threat-feed"><div class="empty">No threats yet. Start the attack simulator.</div></div>
    </div>
    <div class="card">
      <h2>🧠 Immunological Memory</h2>
      <h3 style="font-size:0.85rem;color:#4facfe;margin-bottom:8px;">Known Signatures</h3>
      <div id="sig-feed"><div class="empty">No signatures yet. Memory grows after first attacks.</div></div>
      <br>
      <h3 style="font-size:0.85rem;color:#4facfe;margin-bottom:8px;">Response Playbooks</h3>
      <div id="playbook-feed"><div class="empty">No playbooks yet.</div></div>
    </div>
  </div>

</div>

<div class="toast" id="toast">Threat injected!</div>

<script>
const ICONS = {sql_injection:'💉',brute_force:'🔨',port_scan:'🔭',file_injection:'📁',ddos:'🌊',unknown:'❓'};

async function loadStatus() {
  try {
    const r = await fetch('/status');
    const d = await r.json();
    document.getElementById('m-total').textContent = d.total_threats_seen ?? 0;
    document.getElementById('m-resolved').textContent = d.threats_resolved ?? 0;
    document.getElementById('m-sigs').textContent = d.known_signatures ?? 0;
    document.getElementById('m-playbooks').textContent = d.response_playbooks ?? 0;
    document.getElementById('m-rules').textContent = d.adaptive_rules ?? 0;
    document.getElementById('m-active').textContent = d.active_responses ?? 0;
  } catch(e) {}
}

async function loadThreats() {
  try {
    const r = await fetch('/threats?limit=20');
    const d = await r.json();
    const el = document.getElementById('threat-feed');
    if (!d.threats || d.threats.length === 0) {
      el.innerHTML = '<div class="empty">No threats yet. Start the attack simulator.</div>';
      return;
    }
    el.innerHTML = d.threats.slice(0,15).map(t => {
      const icon = ICONS[t.attack_type] || '❓';
      const sev = t.severity || 'medium';
      const ts = (t.detected_at||'').slice(11,19);
      const rt = t.response_time_seconds ? t.response_time_seconds.toFixed(1)+'s' : '…';
      const status = t.status || 'detected';
      return `<div class="threat-row">
        <span>${icon}</span>
        <span class="badge ${sev}">${sev.toUpperCase()}</span>
        <span style="flex:1;font-size:0.85rem">${t.attack_type.replace(/_/g,' ')} from ${t.source_ip||'?'}</span>
        <span class="status-${status}" style="font-size:0.75rem">${status}</span>
        <span style="color:#8892b0;font-size:0.75rem">${rt}</span>
        <span style="color:#4a5568;font-size:0.75rem">${ts}</span>
      </div>`;
    }).join('');
  } catch(e) {}
}

async function loadMemory() {
  try {
    const [sr, pr] = await Promise.all([
      fetch('/memory/signatures').then(r=>r.json()),
      fetch('/memory/playbooks').then(r=>r.json()),
    ]);
    const sigEl = document.getElementById('sig-feed');
    if (sr.signatures && sr.signatures.length > 0) {
      sigEl.innerHTML = sr.signatures.slice(0,8).map(s =>
        `<div class="sig-row">
          <span class="sig-type">${ICONS[s.attack_type]||'❓'} ${s.attack_type}</span>
          <span class="sig-hits"> · seen ${s.hit_count}x</span>
          <span class="sig-threshold"> · threshold ${s.detection_threshold?.toFixed(2)}</span>
          <div style="color:#4a5568;font-size:0.75rem;margin-top:2px;font-family:monospace">${(s.pattern||'').slice(0,60)}</div>
        </div>`
      ).join('');
    }
    const pbEl = document.getElementById('playbook-feed');
    if (pr.playbooks && pr.playbooks.length > 0) {
      pbEl.innerHTML = pr.playbooks.slice(0,6).map(p => {
        const conf = ((p.confidence_score||0)*100).toFixed(0);
        const confColor = p.confidence_score > 0.7 ? '#30d158' : p.confidence_score > 0.4 ? '#ffd60a' : '#ff6b35';
        return `<div class="sig-row">
          <span class="sig-type">${ICONS[p.attack_type]||'❓'} ${p.attack_type}</span>
          <span style="color:${confColor};font-size:0.75rem"> · ${conf}% confidence</span>
          <span style="color:#8892b0;font-size:0.75rem"> · ✅${p.success_count} ❌${p.failure_count}</span>
        </div>`;
      }).join('');
    }
  } catch(e) {}
}

async function loadAll() {
  await Promise.all([loadStatus(), loadThreats(), loadMemory()]);
  document.getElementById('last-updated').textContent =
    'Last updated: ' + new Date().toLocaleTimeString();
}

async function injectThreat() {
  const type = document.getElementById('f-type').value;
  const ip = document.getElementById('f-ip').value;
  const sev = document.getElementById('f-severity').value;
  try {
    const r = await fetch('/threats/inject', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({event_type:type, source_ip:ip, severity:sev, target_endpoint:'/test', payload_sample:'test'})
    });
    if (r.ok) {
      const toast = document.getElementById('toast');
      toast.style.display = 'block';
      setTimeout(()=>toast.style.display='none', 2500);
      setTimeout(loadAll, 2000);
    }
  } catch(e) { alert('API unreachable'); }
}

loadAll();
setInterval(loadAll, 5000);
</script>
</body>
</html>"""
