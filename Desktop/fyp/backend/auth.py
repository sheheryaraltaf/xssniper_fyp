"""
auth.py — User authentication + password reset using Supabase.
No SQLite. No dummy data. All queries via Supabase client.
"""

import re
import hashlib
import os
import hmac
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List

from backend.supabase_client import db


# ── Password Hashing (PBKDF2-HMAC-SHA256, 600k iterations) ───────────────────
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
    return stored == password   # legacy plain-text migration safety


def is_valid_email(email: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))


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

    # ── Login ──────────────────────────────────────────────────────────────
    @staticmethod
    def authenticate(login: str, password: str) -> Optional[Dict]:
        """Login with email or username."""
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

    # ── Existence checks ────────────────────────────────────────────────────
    @staticmethod
    def username_exists(username: str) -> bool:
        resp = db.table('users').select('id', count='exact').eq('username', username).execute()
        return (resp.count or 0) > 0

    @staticmethod
    def email_exists(email: str) -> bool:
        resp = db.table('users').select('id', count='exact').eq('email', email).execute()
        return (resp.count or 0) > 0

    # ── Register ────────────────────────────────────────────────────────────
    @staticmethod
    def register_user(username: str, email: str, password: str, role: str = 'user') -> bool:
        try:
            db.table('users').insert({
                'username': username,
                'email':    email,
                'password': hash_password(password),
                'role':     role,
            }).execute()
            return True
        except Exception:
            return False

    # ── Admin: list / delete users ──────────────────────────────────────────
    @staticmethod
    def get_all_users() -> List[Dict]:
        resp = db.table('users').select('id, username, email, role').order('id').execute()
        return [
            {'id': r['id'], 'username': r['username'], 'email': r.get('email', ''), 'role': r['role']}
            for r in (resp.data or [])
        ]

    @staticmethod
    def delete_user(user_id: int) -> bool:
        try:
            resp = db.table('users').select('username').eq('id', user_id).single().execute()
            if resp.data and resp.data.get('username') == 'admin':
                return False
            db.table('users').delete().eq('id', user_id).execute()
            return True
        except Exception:
            return False

    # ── Change password (from Settings page — user is logged in) ────────────
    @staticmethod
    def update_password(user_id: int, new_password: str) -> bool:
        try:
            db.table('users').update({'password': hash_password(new_password)}).eq('id', user_id).execute()
            return True
        except Exception:
            return False

    @staticmethod
    def verify_current_password(user_id: int, current_password: str) -> bool:
        """Verify existing password before allowing a change."""
        try:
            resp = db.table('users').select('password').eq('id', user_id).single().execute()
            if not resp.data:
                return False
            return verify_password(current_password, resp.data['password'])
        except Exception:
            return False

    # ── Forgot Password ──────────────────────────────────────────────────────
    @staticmethod
    def get_user_by_email(email: str) -> Optional[Dict]:
        """Return user dict if email exists, else None."""
        resp = db.table('users') \
                 .select('id, username, email, role') \
                 .eq('email', email) \
                 .limit(1) \
                 .execute()
        rows = resp.data or []
        if not rows:
            return None
        r = rows[0]
        return {'id': r['id'], 'username': r['username'], 'email': r.get('email', ''), 'role': r['role']}

    @staticmethod
    def create_password_reset_token(user_id: int) -> str:
        """
        Generate a secure random token, store it in Supabase with 1-hour expiry,
        delete any previous tokens for this user, and return the token string.
        """
        # Delete old tokens for this user first
        db.table('password_resets').delete().eq('user_id', user_id).execute()

        token      = secrets.token_urlsafe(48)   # 64-char URL-safe string
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        db.table('password_resets').insert({
            'user_id':    user_id,
            'token':      token,
            'expires_at': expires_at,
        }).execute()

        return token

    @staticmethod
    def verify_reset_token(token: str) -> Optional[Dict]:
        """
        Return the user associated with the token if it is valid and not expired.
        Returns None if token is invalid, expired, or not found.
        """
        try:
            resp = db.table('password_resets') \
                     .select('user_id, expires_at') \
                     .eq('token', token) \
                     .single() \
                     .execute()
            if not resp.data:
                return None

            expires_at = datetime.fromisoformat(resp.data['expires_at'])
            # Make sure both are timezone-aware for comparison
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if datetime.now(timezone.utc) > expires_at:
                # Token expired — clean it up
                db.table('password_resets').delete().eq('token', token).execute()
                return None

            user_id = resp.data['user_id']
            user_resp = db.table('users') \
                          .select('id, username, email, role') \
                          .eq('id', user_id) \
                          .single() \
                          .execute()
            return user_resp.data or None

        except Exception:
            return None

    @staticmethod
    def consume_reset_token(token: str, new_password: str) -> bool:
        """
        Validate token, update the user's password, and delete the token.
        Returns True on success, False on failure.
        """
        user = AuthManager.verify_reset_token(token)
        if not user:
            return False
        try:
            db.table('users').update({
                'password': hash_password(new_password)
            }).eq('id', user['id']).execute()
            db.table('password_resets').delete().eq('token', token).execute()
            return True
        except Exception:
            return False
