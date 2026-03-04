"""
auth.py — User authentication using Supabase as the data store.
No SQLite. All queries go through the shared Supabase client.
"""

import re
import hashlib
import os
import hmac
from typing import Optional, Dict, List

from backend.supabase_client import db

# ── Password Hashing (PBKDF2-HMAC-SHA256) ─────────────────────────────────────
_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    salt = os.urandom(32)
    key  = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, _ITERATIONS)
    return f"pbkdf2${salt.hex()}${key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if stored.startswith('pbkdf2$'):
        try:
            _, salt_hex, key_hex = stored.split('$')
            salt     = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(key_hex)
            computed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, _ITERATIONS)
            return hmac.compare_digest(computed, expected)
        except Exception:
            return False
    # Legacy plain-text (migration safety)
    return stored == password


def is_valid_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def password_meets_requirements(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password needs at least one uppercase letter (A-Z)"
    if not re.search(r'[a-z]', password):
        return False, "Password needs at least one lowercase letter (a-z)"
    if not re.search(r'[0-9]', password):
        return False, "Password needs at least one number (0-9)"
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password needs at least one special character (!@#$...)"
    return True, ""


class AuthManager:

    @staticmethod
    def authenticate(login: str, password: str) -> Optional[Dict]:
        """Login with email or username."""
        # Try username first, then email
        resp = db.table('users') \
                 .select('id, username, email, role, password') \
                 .or_(f'username.eq.{login},email.eq.{login}') \
                 .limit(1) \
                 .execute()

        rows = resp.data or []
        if not rows:
            return None
        row = rows[0]
        if verify_password(password, row['password']):
            return {
                'id':       row['id'],
                'username': row['username'],
                'email':    row.get('email', ''),
                'role':     row['role'],
            }
        return None

    @staticmethod
    def username_exists(username: str) -> bool:
        resp = db.table('users').select('id', count='exact').eq('username', username).execute()
        return (resp.count or 0) > 0

    @staticmethod
    def email_exists(email: str) -> bool:
        resp = db.table('users').select('id', count='exact').eq('email', email).execute()
        return (resp.count or 0) > 0

    @staticmethod
    def register_user(username: str, email: str, password: str, role: str = 'user') -> bool:
        try:
            hashed = hash_password(password)
            db.table('users').insert({
                'username': username,
                'email':    email,
                'password': hashed,
                'role':     role,
            }).execute()
            return True
        except Exception:
            return False

    @staticmethod
    def get_all_users() -> List[Dict]:
        resp = db.table('users') \
                 .select('id, username, email, role') \
                 .order('id') \
                 .execute()
        return [
            {
                'id':       r['id'],
                'username': r['username'],
                'email':    r.get('email', ''),
                'role':     r['role'],
            }
            for r in (resp.data or [])
        ]

    @staticmethod
    def delete_user(user_id: int) -> bool:
        try:
            # Prevent deletion of the admin account
            resp = db.table('users').select('username').eq('id', user_id).single().execute()
            if resp.data and resp.data.get('username') == 'admin':
                return False
            db.table('users').delete().eq('id', user_id).execute()
            return True
        except Exception:
            return False

    @staticmethod
    def update_password(user_id: int, new_password: str) -> bool:
        try:
            hashed = hash_password(new_password)
            db.table('users').update({'password': hashed}).eq('id', user_id).execute()
            return True
        except Exception:
            return False
