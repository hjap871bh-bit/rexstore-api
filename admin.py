import sqlite3
import sys
from datetime import datetime, timedelta
import secrets

DB_PATH = "rexstore.db"

def generate_key(days: int):
    raw = secrets.token_hex(8).upper()
    key = f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"
    expires = (datetime.utcnow() + timedelta(days=days)).isoformat() if days > 0 else None
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO licenses (key, expires_at, created_at, banned) VALUES (?, ?, ?, 0)",
              (key, expires, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    print(f"Generated: {key} | Expires: {expires or 'Never'}")

def list_keys():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT key, hwid, expires_at, banned, last_seen FROM licenses")
    for row in c.fetchall():
        print(row)
    conn.close()

def ban_key(key: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE licenses SET banned = 1 WHERE key = ?", (key,))
    conn.commit()
    conn.close()
    print(f"Banned: {key}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python admin.py [gen DAYS | list | ban KEY]")
        sys.exit(1)
    
    cmd = sys.argv[1]
    if cmd == "gen":
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        generate_key(days)
    elif cmd == "list":
        list_keys()
    elif cmd == "ban":
        ban_key(sys.argv[2])
