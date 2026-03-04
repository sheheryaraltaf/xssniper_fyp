import os
from dotenv import load_dotenv
load_dotenv()

SUPABASE_URL             = os.getenv("SUPABASE_URL")
SUPABASE_SECRET_KEY      = os.getenv("SUPABASE_SECRET_KEY")
SUPABASE_PUBLISHABLE_KEY = os.getenv("SUPABASE_PUBLISHABLE_KEY")

BG_PRIMARY   = '#020408'
BG_CARD      = '#0a1520'
ACCENT_GREEN = '#00ff88'
ACCENT_RED   = '#ff3b5c'
ACCENT_BLUE  = '#00d9ff'
BG_SECONDARY = '#060d12'
