from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
import sqlite3
import hashlib
import secrets
import os

app = FastAPI(title="RexStore API", docs_url=None, redoc_url=None)

DB_PATH = "rexstore.db"
SECRET = os.environ.get("REXSTORE_SECRET", "change_me_in_production")

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
