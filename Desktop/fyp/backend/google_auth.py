"""
Google OAuth2 — XSSniper
User persistence via Supabase (no SQLite).
"""

import httpx
import urllib.parse
from typing import Optional, Dict
from backend.supabase_client import db

GOOGLE_CLIENT_ID     = '289407265503-mirpj1sbqllocfm12mmu7jdd4a69p1ue.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'
GOOGLE_REDIRECT_URI  = 'http://127.0.0.1:8080/auth/google/callback'

GOOGLE_AUTH_URL  = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USER_URL  = 'https://www.googleapis.com/oauth2/v3/userinfo'


def get_google_login_url() -> str:
    params = {
        'client_id':     GOOGLE_CLIENT_ID,
        'redirect_uri':  GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope':         'openid email profile',
        'access_type':   'online',
        'prompt':        'select_account',
    }
    return GOOGLE_AUTH_URL + '?' + urllib.parse.urlencode(params)


async def exchange_google_code(code: str) -> Optional[str]:
    async with httpx.AsyncClient() as client:
        resp = await client.post(GOOGLE_TOKEN_URL, data={
            'code':          code,
            'client_id':     GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri':  GOOGLE_REDIRECT_URI,
            'grant_type':    'authorization_code',
        })
        return resp.json().get('access_token')


async def get_google_user(token: str) -> Optional[Dict]:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            GOOGLE_USER_URL,
            headers={'Authorization': f'Bearer {token}'}
        )
        if resp.status_code != 200:
            return None
        return resp.json()


def get_or_create_google_user(google_user: Dict) -> Dict:
    """Find existing user by email, or auto-create from Google profile — stored in Supabase."""
    email     = google_user.get('email', '')
    raw_name  = google_user.get('given_name') or email.split('@')[0]
    username  = ''.join(c for c in raw_name if c.isalnum() or c == '_')[:20] or 'user'
    google_id = google_user.get('sub', '')

    # Return existing user if email already registered
    resp = db.table('users') \
             .select('id, username, email, role') \
             .eq('email', email) \
             .limit(1) \
             .execute()

    existing = resp.data or []
    if existing:
        r = existing[0]
        return {'id': r['id'], 'username': r['username'], 'email': r.get('email', ''), 'role': r['role']}

    # Ensure unique username
    base, counter, final_username = username, 1, username
    while True:
        chk = db.table('users').select('id', count='exact').eq('username', final_username).execute()
        if (chk.count or 0) == 0:
            break
        final_username = f"{base}{counter}"
        counter += 1

    insert_resp = db.table('users').insert({
        'username': final_username,
        'email':    email,
        'password': f'google_{google_id}',   # OAuth users cannot use password login
        'role':     'user',
    }).execute()

    new = insert_resp.data[0]
    return {'id': new['id'], 'username': new['username'], 'email': new.get('email', ''), 'role': 'user'}
