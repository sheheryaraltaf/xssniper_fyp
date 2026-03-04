"""
GitHub OAuth2 — XSSniper
User persistence via Supabase (no SQLite).
"""

import httpx
from typing import Optional, Dict
from backend.supabase_client import db

GITHUB_CLIENT_ID     = 'Ov23liQQ7EmlmJwJIlfh'
GITHUB_CLIENT_SECRET = 'f4c58f186be836c00bf0fc7ccd191a9a0ac19feb'
GITHUB_REDIRECT_URI  = 'http://localhost:8080/auth/github/callback'


def get_github_login_url() -> str:
    return (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={GITHUB_REDIRECT_URI}"
        f"&scope=user:email"
    )


async def exchange_code_for_token(code: str) -> Optional[str]:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            'https://github.com/login/oauth/access_token',
            data={
                'client_id':     GITHUB_CLIENT_ID,
                'client_secret': GITHUB_CLIENT_SECRET,
                'code':          code,
                'redirect_uri':  GITHUB_REDIRECT_URI,
            },
            headers={'Accept': 'application/json'}
        )
        return resp.json().get('access_token')


async def get_github_user(token: str) -> Optional[Dict]:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            'https://api.github.com/user',
            headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
        )
        if resp.status_code != 200:
            return None
        user = resp.json()

        # Fetch primary email if not public
        if not user.get('email'):
            email_resp = await client.get(
                'https://api.github.com/user/emails',
                headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
            )
            emails = email_resp.json()
            primary = next((e['email'] for e in emails if e.get('primary')), None)
            user['email'] = primary

        return user


def get_or_create_github_user(github_user: Dict) -> Dict:
    """Find existing user or create new one from GitHub profile — stored in Supabase."""
    username  = github_user.get('login', '')
    email     = github_user.get('email', '') or f"{username}@github.com"
    github_id = str(github_user.get('id', ''))

    # Check if user already exists (by email or username)
    resp = db.table('users') \
             .select('id, username, email, role') \
             .or_(f'email.eq.{email},username.eq.{username}') \
             .limit(1) \
             .execute()

    existing = (resp.data or [])
    if existing:
        r = existing[0]
        return {'id': r['id'], 'username': r['username'], 'email': r.get('email', ''), 'role': r['role']}

    # Ensure username uniqueness
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
        'password': f'github_{github_id}',   # OAuth users cannot use password login
        'role':     'user',
    }).execute()

    new = insert_resp.data[0]
    return {'id': new['id'], 'username': new['username'], 'email': new.get('email', ''), 'role': 'user'}
