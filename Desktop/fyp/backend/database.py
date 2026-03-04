"""
database.py — All database interactions via Supabase (PostgreSQL).
No SQLite. No mock data. Real Supabase REST API calls only.
"""

import json
import hashlib
import os
from datetime import datetime, timezone, timedelta
from backend.supabase_client import db


# ── Password helper (used only for seeding the default admin) ─────────────────
_ITERATIONS = 600_000

def _hash_default(pw: str) -> str:
    salt = os.urandom(32)
    key  = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, _ITERATIONS)
    return f"pbkdf2${salt.hex()}${key.hex()}"


# ── Initialise: ensure admin user exists ──────────────────────────────────────
def init_database():
    """
    Called once at startup.
    Tables must already exist in Supabase (run schema.sql in the SQL Editor).
    This function only seeds the default admin account if the users table is empty.
    """
    resp = db.table('users').select('id', count='exact').execute()
    if resp.count == 0:
        hashed = _hash_default('Admin@1234')
        db.table('users').insert({
            'username': 'admin',
            'email':    'admin@xssniper.com',
            'password': hashed,
            'role':     'admin',
        }).execute()


# ── Dashboard stats ───────────────────────────────────────────────────────────
def get_stats() -> dict:
    # Total scans & total vulnerabilities
    scans_resp = db.table('scans').select('vulnerabilities, status, date').execute()
    rows = scans_resp.data or []

    total = len(rows)
    vulns = sum(r.get('vulnerabilities', 0) or 0 for r in rows)

    # Health: % of scans in the last 7 days that completed successfully
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    recent = [r for r in rows if r.get('date', '') >= cutoff]
    if recent:
        completed = sum(1 for r in recent if r.get('status') == 'Completed')
        health = round(completed * 100.0 / len(recent), 1)
    else:
        health = 100.0

    return {'total': total, 'vulns': vulns, 'health': health}


# ── Scan history ──────────────────────────────────────────────────────────────
def get_history() -> list:
    resp = db.table('scans') \
             .select('id, date, url, status, vulnerabilities, duration') \
             .order('date', desc=True) \
             .limit(100) \
             .execute()

    return [
        {
            'id':              r['id'],
            'date':            (r.get('date') or '')[:19],
            'url':             r.get('url', ''),
            'status':          r.get('status', ''),
            'vulnerabilities': r.get('vulnerabilities', 0),
            'duration':        f"{r['duration']:.2f}s" if r.get('duration') else 'N/A',
        }
        for r in (resp.data or [])
    ]


# ── Single scan detail ────────────────────────────────────────────────────────
def get_scan_detail(scan_id: int) -> dict | None:
    resp = db.table('scans').select('*').eq('id', scan_id).single().execute()
    r = resp.data
    if not r:
        return None
    return {
        'id':              r['id'],
        'date':            r.get('date', ''),
        'url':             r.get('url', ''),
        'status':          r.get('status', ''),
        'vulnerabilities': r.get('vulnerabilities', 0),
        'log_output':      r.get('log_output', ''),
        'config':          json.loads(r['config']) if r.get('config') else {},
        'duration':        r.get('duration', 0),
    }


# ── Save a finished scan ──────────────────────────────────────────────────────
def save_scan(url: str, status: str, vulns: int,
              log: str, config: str, duration: float) -> None:
    db.table('scans').insert({
        'date':            datetime.now(timezone.utc).isoformat(),
        'url':             url,
        'status':          status,
        'vulnerabilities': vulns,
        'log_output':      log,
        'config':          config,
        'duration':        duration,
    }).execute()


# ── Delete a scan ─────────────────────────────────────────────────────────────
def delete_scan(scan_id: int) -> bool:
    try:
        db.table('scans').delete().eq('id', scan_id).execute()
        return True
    except Exception:
        return False
