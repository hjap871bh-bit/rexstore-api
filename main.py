from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
import sqlite3
import hashlib
import secrets
import os

app = FastAPI(title="RexStore API", docs_url=None, redoc_url=None)

DB_PATH = "rexstore.db"
SECRET = os.environ.get("REXSTORE_SECRET", "change_me_in_production")
ADMIN_PASS = os.environ.get("REXSTORE_ADMIN_PASS", "admin123")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            hwid TEXT,
            expires_at TEXT,
            created_at TEXT,
            last_seen TEXT,
            banned INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            key TEXT,
            hwid TEXT,
            created_at TEXT,
            expires_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

class AuthRequest(BaseModel):
    key: str
    hwid: str

class HeartbeatRequest(BaseModel):
    token: str
    hwid: str

class GenerateRequest(BaseModel):
    days: int
    count: int = 1
    password: str

def hash_hwid(hwid: str) -> str:
    return hashlib.sha256((hwid + SECRET).encode()).hexdigest()[:32]

def generate_token() -> str:
    return secrets.token_urlsafe(48)

@app.get("/")
def root():
    return {"status": "ok", "service": "RexStore"}

@app.post("/auth")
def auth(req: AuthRequest):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT key, hwid, expires_at, banned FROM licenses WHERE key = ?", (req.key,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        raise HTTPException(401, "Invalid license key")
    
    key, stored_hwid, expires_at, banned = row
    
    if banned:
        conn.close()
        raise HTTPException(403, "License banned")
    
    if expires_at:
        exp = datetime.fromisoformat(expires_at)
        if datetime.utcnow() > exp:
            conn.close()
            raise HTTPException(403, "License expired")
    
    hashed = hash_hwid(req.hwid)
    if stored_hwid and stored_hwid != hashed:
        conn.close()
        raise HTTPException(403, "HWID mismatch")
    
    if not stored_hwid:
        c.execute("UPDATE licenses SET hwid = ?, last_seen = ? WHERE key = ?",
                  (hashed, datetime.utcnow().isoformat(), req.key))
    
    token = generate_token()
    session_exp = datetime.utcnow() + timedelta(hours=24)
    c.execute("INSERT INTO sessions (token, key, hwid, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
              (token, req.key, hashed, datetime.utcnow().isoformat(), session_exp.isoformat()))
    
    c.execute("UPDATE licenses SET last_seen = ? WHERE key = ?",
              (datetime.utcnow().isoformat(), req.key))
    
    conn.commit()
    conn.close()
    
    time_left = None
    if expires_at:
        delta = datetime.fromisoformat(expires_at) - datetime.utcnow()
        time_left = max(0, int(delta.total_seconds()))
    
    return {
        "status": "ok",
        "token": token,
        "expires_in": 86400,
        "license_time_left": time_left
    }

@app.post("/heartbeat")
def heartbeat(req: HeartbeatRequest):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT token, key, hwid, expires_at FROM sessions WHERE token = ?", (req.token,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        raise HTTPException(401, "Invalid session")
    
    token, key, stored_hwid, sess_exp = row
    
    if datetime.utcnow() > datetime.fromisoformat(sess_exp):
        c.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        raise HTTPException(401, "Session expired")
    
    hashed = hash_hwid(req.hwid)
    if hashed != stored_hwid:
        conn.close()
        raise HTTPException(403, "HWID mismatch")
    
    c.execute("SELECT expires_at, banned FROM licenses WHERE key = ?", (key,))
    lic = c.fetchone()
    if not lic or lic[1]:
        conn.close()
        raise HTTPException(403, "License revoked")
    
    expires_at = lic[0]
    time_left = None
    if expires_at:
        delta = datetime.fromisoformat(expires_at) - datetime.utcnow()
        time_left = max(0, int(delta.total_seconds()))
        if time_left <= 0:
            conn.close()
            raise HTTPException(403, "License expired")
    
    conn.commit()
    conn.close()
    return {"status": "ok", "license_time_left": time_left}

# ==================== Admin Panel ====================
@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>RexStore Admin</title>
        <meta charset="UTF-8">
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background: #0a0a0a; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; padding: 30px; }
            h1 { color: #fff; margin-bottom: 20px; font-weight: 300; letter-spacing: 2px; }
            .card { background: #141414; border: 1px solid #222; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
            .card h2 { color: #888; font-size: 14px; text-transform: uppercase; margin-bottom: 15px; letter-spacing: 1px; }
            input, select { background: #0a0a0a; border: 1px solid #333; color: #e0e0e0; padding: 10px; border-radius: 4px; margin-right: 10px; font-size: 14px; }
            input:focus, select:focus { outline: none; border-color: #6c5ce7; }
            button { background: #6c5ce7; border: none; color: #fff; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-size: 14px; }
            button:hover { background: #5a4bd1; }
            button.danger { background: #d63031; }
            button.danger:hover { background: #b71c1c; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #222; font-size: 13px; }
            th { color: #666; text-transform: uppercase; font-size: 11px; }
            .key { font-family: monospace; color: #00b894; }
            .banned { color: #d63031; }
            .active { color: #00b894; }
            .msg { padding: 10px; border-radius: 4px; margin-bottom: 10px; display: none; }
            .msg.ok { background: #00b89420; color: #00b894; display: block; }
            .msg.err { background: #d6303120; color: #d63031; display: block; }
        </style>
    </head>
    <body>
        <h1>REXSTORE ADMIN</h1>
        
        <div class="card">
            <h2>Generate Keys</h2>
            <div id="msg" class="msg"></div>
            <input type="password" id="pass" placeholder="Admin Password" style="width: 200px;">
            <select id="days">
                <option value="1">1 Day</option>
                <option value="7">7 Days</option>
                <option value="30">30 Days</option>
                <option value="0">Lifetime</option>
            </select>
            <input type="number" id="count" value="1" min="1" max="50" style="width: 80px;">
            <button onclick="generate()">Generate</button>
        </div>

        <div class="card">
            <h2>Licenses</h2>
            <table id="keys-table">
                <thead>
                    <tr>
                        <th>Key</th>
                        <th>HWID</th>
                        <th>Expires</th>
                        <th>Last Seen</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>

        <script>
            let currentPass = '';

            async function generate() {
                const pass = document.getElementById('pass').value;
                const days = parseInt(document.getElementById('days').value);
                const count = parseInt(document.getElementById('count').value);
                currentPass = pass;

                const res = await fetch('/admin/generate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({days, count, password: pass})
                });

                const msg = document.getElementById('msg');
                if (res.ok) {
                    const data = await res.json();
                    msg.className = 'msg ok';
                    msg.textContent = 'Generated: ' + data.keys.join(', ');
                    loadKeys();
                } else {
                    msg.className = 'msg err';
                    msg.textContent = 'Wrong password';
                }
            }

            async function loadKeys() {
                if (!currentPass) return;
                const res = await fetch('/admin/keys?password=' + encodeURIComponent(currentPass));
                if (!res.ok) return;
                const data = await res.json();
                const tbody = document.querySelector('#keys-table tbody');
                tbody.innerHTML = '';
                data.keys.forEach(k => {
                    const tr = document.createElement('tr');
                    const exp = k.expires_at ? new Date(k.expires_at).toLocaleDateString() : 'Never';
                    const lastSeen = k.last_seen ? new Date(k.last_seen).toLocaleString() : 'Never';
                    tr.innerHTML = `
                        <td class="key">${k.key}</td>
                        <td>${k.hwid ? k.hwid.substring(0, 12) + '...' : '—'}</td>
                        <td>${exp}</td>
                        <td>${lastSeen}</td>
                        <td class="${k.banned ? 'banned' : 'active'}">${k.banned ? 'BANNED' : 'ACTIVE'}</td>
                        <td><button class="danger" onclick="banKey('${k.key}')">Ban</button></td>
                    `;
                    tbody.appendChild(tr);
                });
            }

            async function banKey(key) {
                if (!currentPass) return;
                const res = await fetch('/admin/ban', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key, password: currentPass})
                });
                if (res.ok) loadKeys();
            }
        </script>
    </body>
    </html>
    """

@app.post("/admin/generate")
def admin_generate(req: GenerateRequest):
    if req.password != ADMIN_PASS:
        raise HTTPException(401, "Wrong password")
    
    keys = []
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    for _ in range(req.count):
        raw = secrets.token_hex(8).upper()
        key = f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"
        expires = (datetime.utcnow() + timedelta(days=req.days)).isoformat() if req.days > 0 else None
        c.execute("INSERT INTO licenses (key, expires_at, created_at, banned) VALUES (?, ?, ?, 0)",
                  (key, expires, datetime.utcnow().isoformat()))
        keys.append(key)
    
    conn.commit()
    conn.close()
    return {"status": "ok", "keys": keys}

@app.get("/admin/keys")
def admin_keys(password: str):
    if password != ADMIN_PASS:
        raise HTTPException(401, "Wrong password")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT key, hwid, expires_at, last_seen, banned FROM licenses ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    
    return {"keys": [
        {"key": r[0], "hwid": r[1], "expires_at": r[2], "last_seen": r[3], "banned": bool(r[4])}
        for r in rows
    ]}

class BanRequest(BaseModel):
    key: str
    password: str

@app.post("/admin/ban")
def admin_ban(req: BanRequest):
    if req.password != ADMIN_PASS:
        raise HTTPException(401, "Wrong password")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE licenses SET banned = 1 WHERE key = ?", (req.key,))
    conn.commit()
    conn.close()
    return {"status": "ok"}
