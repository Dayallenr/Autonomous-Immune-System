"""
Streamlit Dashboard — optional enhanced monitoring UI.
Requires: pip install streamlit plotly

The built-in dashboard is available at http://localhost:8000/dashboard
without any additional dependencies.

Run with: streamlit run dashboard/app.py
"""
try:
    import streamlit as st
    import plotly.express as px
    _STREAMLIT_AVAILABLE = True
except ImportError:
    _STREAMLIT_AVAILABLE = False

import time
from datetime import datetime
from typing import Optional

import httpx
import pandas as pd

API_URL = "http://localhost:8000"
REFRESH_INTERVAL = 5

if not _STREAMLIT_AVAILABLE:
    print("Streamlit is not installed.")
    print("The built-in dashboard is available at http://localhost:8000/dashboard")
    print("To install Streamlit: pip install streamlit plotly")
    exit(0)

st.set_page_config(
    page_title="AI Immune System",
    page_icon="🧬",
    layout="wide",
    initial_sidebar_state="expanded",
)

SEVERITY_COLORS = {
    "critical": "#ff2d55",
    "high": "#ff6b35",
    "medium": "#ffd60a",
    "low": "#30d158",
}

ATTACK_ICONS = {
    "sql_injection": "💉",
    "brute_force": "🔨",
    "port_scan": "🔭",
    "file_injection": "📁",
    "ddos": "🌊",
    "connection_flood": "🌊",
    "unknown": "❓",
}


@st.cache_data(ttl=REFRESH_INTERVAL)
def fetch(endpoint: str) -> Optional[dict]:
    try:
        with httpx.Client(timeout=3) as client:
            return client.get(f"{API_URL}{endpoint}").json()
    except Exception:
        return None


st.markdown(
    "<h1 style='color:#4facfe;'>🧬 Autonomous AI Immune System</h1>"
    "<p style='color:#8892b0;'>Real-time threat detection, autonomous response, and immunological learning</p>",
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("### Controls")
    auto_refresh = st.toggle("Auto-refresh", value=True)
    if not auto_refresh and st.button("Refresh Now"):
        st.cache_data.clear()
        st.rerun()

    st.divider()
    st.markdown("### Inject Test Threat")
    attack_type = st.selectbox("Attack Type", ["sql_injection", "brute_force", "port_scan", "file_injection", "ddos"])
    source_ip = st.text_input("Source IP", "10.0.1.99")
    severity = st.select_slider("Severity", ["low", "medium", "high", "critical"], value="high")

    if st.button("🚨 Inject", type="primary"):
        try:
            with httpx.Client(timeout=5) as client:
                resp = client.post(
                    f"{API_URL}/threats/inject",
                    json={"event_type": attack_type, "source_ip": source_ip, "severity": severity,
                          "target_endpoint": "/test", "payload_sample": f"test {attack_type}"},
                )
            st.success("Threat injected!") if resp.status_code == 200 else st.error(f"Error: {resp.status_code}")
            st.cache_data.clear()
        except Exception as e:
            st.error(f"API unreachable: {e}")

# Load data
status_data = fetch("/status")
threats_data = fetch("/threats?limit=100")
sigs_data = fetch("/memory/signatures")
playbooks_data = fetch("/memory/playbooks")

if not status_data:
    st.error("Cannot connect to API. Start with: `uvicorn api.main:app --port 8000`")
    st.stop()

# Metrics row
c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Status", "🟢 Active")
c2.metric("Threats Seen", status_data.get("total_threats_seen", 0))
c3.metric("Resolved", status_data.get("threats_resolved", 0))
c4.metric("Signatures", status_data.get("known_signatures", 0))
c5.metric("Playbooks", status_data.get("response_playbooks", 0))
c6.metric("Adaptive Rules", status_data.get("adaptive_rules", 0))

st.divider()

threats = (threats_data or {}).get("threats", [])

# Charts
if threats:
    df = pd.DataFrame(threats)
    ch1, ch2 = st.columns(2)

    with ch1:
        st.markdown("#### Threats by Type")
        type_counts = df["attack_type"].value_counts().reset_index()
        type_counts.columns = ["attack_type", "count"]
        fig = px.bar(type_counts, x="attack_type", y="count",
                     color="count", color_continuous_scale=["#1a3a5c", "#4facfe"])
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                          font_color="#8892b0", coloraxis_showscale=False, margin=dict(t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)

    with ch2:
        st.markdown("#### Severity Distribution")
        sev_counts = df["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        fig = px.pie(sev_counts, values="count", names="severity",
                     color="severity", color_discrete_map=SEVERITY_COLORS, hole=0.5)
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#8892b0", margin=dict(t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)

st.markdown("#### Live Threat Feed")
if threats:
    for t in threats[:15]:
        sev = t.get("severity", "medium")
        attack = t.get("attack_type", "unknown")
        with st.expander(
            f"{ATTACK_ICONS.get(attack,'❓')} [{sev.upper()}] {attack.replace('_',' ').title()} "
            f"— {t.get('source_ip','?')} | {(t.get('detected_at',''))[:19]}"
        ):
            tc1, tc2, tc3, tc4 = st.columns(4)
            tc1.metric("Status", t.get("status", "detected"))
            tc2.metric("Blocked", "Yes" if t.get("was_blocked") else "No")
            tc3.metric("Confidence", f"{t.get('confidence_score', 0):.0%}")
            tc4.metric("Response", f"{t.get('response_time_seconds',0):.1f}s" if t.get("response_time_seconds") else "…")
            if t.get("investigator_analysis"):
                st.info(t["investigator_analysis"])
else:
    st.info("No threats yet. Run: `python -m simulation.attack_simulator`")

st.divider()

# Memory section
mc1, mc2 = st.columns(2)
sigs = (sigs_data or {}).get("signatures", [])
playbooks = (playbooks_data or {}).get("playbooks", [])

with mc1:
    st.markdown("#### 🧠 Known Signatures")
    for s in sigs[:8]:
        conf_drop = round((0.7 - s.get("detection_threshold", 0.7)) * 100, 1)
        st.markdown(
            f"**{ATTACK_ICONS.get(s['attack_type'],'❓')} {s['attack_type']}** "
            f"— seen {s['hit_count']}x | threshold: {s.get('detection_threshold',0.7):.2f}"
            + (f" ↓{conf_drop}% (immune memory)" if conf_drop > 0 else "")
        )

with mc2:
    st.markdown("#### 📚 Response Playbooks")
    for p in playbooks[:6]:
        conf = p.get("confidence_score", 0)
        color = "green" if conf > 0.7 else "orange" if conf > 0.4 else "red"
        st.markdown(
            f"**{ATTACK_ICONS.get(p['attack_type'],'❓')} {p['attack_type']}** "
            f"({p.get('severity','?')}) — :{color}[{conf:.0%}] "
            f"✅{p.get('success_count',0)} ❌{p.get('failure_count',0)}"
        )

st.markdown(
    f"<div style='text-align:center;color:#4a5568;font-size:0.8rem;padding:20px 0'>"
    f"Last updated: {datetime.utcnow().strftime('%H:%M:%S UTC')} | API: {API_URL}"
    f"</div>",
    unsafe_allow_html=True,
)

if auto_refresh:
    time.sleep(REFRESH_INTERVAL)
    st.cache_data.clear()
    st.rerun()
