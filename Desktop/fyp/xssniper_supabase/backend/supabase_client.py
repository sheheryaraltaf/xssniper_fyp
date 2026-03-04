"""
Shared Supabase client — import `db` anywhere in the backend.
Uses the secret key to bypass Row Level Security for all server-side operations.
"""
from supabase import create_client, Client
from backend.config import SUPABASE_URL, SUPABASE_SECRET_KEY

db: Client = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)
