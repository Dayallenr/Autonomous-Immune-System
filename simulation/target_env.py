"""
Simulation Target Environment — an intentionally vulnerable web app.
Acts as the "body" that the immune system protects.
Logs all requests to a file that the sensors monitor.
"""
import json
import os
import time
import sqlite3
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

os.makedirs("logs", exist_ok=True)
REQUEST_LOG = "logs/target_requests.log"
DB_QUERY_LOG = "logs/target_db_queries.log"

# In-memory user store (vulnerable: raw SQL via sqlite3)
DB_PATH = "simulation_target.db"

app = FastAPI(title="Simulation Target", description="Vulnerable app for immune system testing")


# ─────────────────────────────────────────────
# DB setup
# ─────────────────────────────────────────────

def _get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    conn = _get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            filename TEXT,
            content TEXT,
            uploaded_at TEXT
        )
    """)
    # Seed users
    existing = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if existing == 0:
        conn.executemany(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            [
                ("admin", "admin123", "admin"),
                ("alice", "password1", "user"),
                ("bob", "letmein", "user"),
            ],
        )
    conn.commit()
    conn.close()


_init_db()


# ─────────────────────────────────────────────
# Logging middleware
# ─────────────────────────────────────────────

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    body = b""
    if request.method in ("POST", "PUT", "PATCH"):
        body = await request.body()

    response = await call_next(request)
    duration_ms = (time.time() - start) * 1000

    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": request.client.host if request.client else "unknown",
        "method": request.method,
        "path": str(request.url.path),
        "query": str(request.url.query),
        "status_code": response.status_code,
        "duration_ms": round(duration_ms, 2),
        "body_sample": body[:200].decode("utf-8", errors="replace") if body else "",
        "headers": dict(request.headers),
    }

    with open(REQUEST_LOG, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    return response


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
async def login(req: LoginRequest):
    """VULNERABLE: raw string interpolation into SQL (SQL injection target)."""
    conn = _get_db()

    # Intentionally vulnerable query
    query = f"SELECT * FROM users WHERE username = '{req.username}' AND password = '{req.password}'"

    _log_db_query(query, "login")

    try:
        result = conn.execute(query).fetchone()
        conn.close()
    except sqlite3.OperationalError as e:
        conn.close()
        raise HTTPException(status_code=400, detail=str(e))

    if result:
        return {"status": "ok", "message": f"Welcome, {result['username']}!", "role": result["role"]}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/users/{user_id}")
async def get_user(user_id: int):
    """VULNERABLE: IDOR — no authorization check."""
    conn = _get_db()
    result = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(result)


@app.get("/search")
async def search(q: str = ""):
    """VULNERABLE: command injection via search param (simulated)."""
    _log_db_query(f"SELECT * FROM users WHERE username LIKE '%{q}%'", "search")

    # Detect obvious command injection patterns in logs for sensor to pick up
    dangerous = ["&&", ";", "|", "`", "$(", "../", "/etc/passwd"]
    is_dangerous = any(d in q for d in dangerous)
    if is_dangerous:
        return {"warning": "Suspicious input detected", "query": q, "results": []}

    conn = _get_db()
    results = conn.execute(
        f"SELECT id, username FROM users WHERE username LIKE '%{q}%'"
    ).fetchall()
    conn.close()
    return {"results": [dict(r) for r in results]}


class UploadRequest(BaseModel):
    filename: str
    content: str


@app.post("/upload")
async def upload_file(req: UploadRequest):
    """VULNERABLE: no validation of filename or content (file injection target)."""
    conn = _get_db()
    conn.execute(
        "INSERT INTO files (filename, content, uploaded_at) VALUES (?, ?, ?)",
        (req.filename, req.content, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()
    return {"status": "uploaded", "filename": req.filename}


@app.get("/files")
async def list_files():
    conn = _get_db()
    files = conn.execute("SELECT id, filename, uploaded_at FROM files").fetchall()
    conn.close()
    return {"files": [dict(f) for f in files]}


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.get("/admin")
async def admin_panel():
    """VULNERABLE: no auth check."""
    conn = _get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return {"users": [dict(u) for u in users], "message": "Admin panel — no auth required!"}


@app.get("/config")
async def config_endpoint():
    """Simulates a config endpoint that leaks information."""
    return {
        "db_path": DB_PATH,
        "version": "1.0.0",
        "debug": True,
        "secret_key": "SUPER_SECRET_DO_NOT_SHARE",
    }


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _log_db_query(query: str, context: str):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "context": context,
        "query": query,
    }
    with open(DB_QUERY_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
