import os
from dotenv import load_dotenv
load_dotenv()

# ── Supabase ──────────────────────────────────────────────────
SUPABASE_URL             = os.getenv("SUPABASE_URL")
SUPABASE_SECRET_KEY      = os.getenv("SUPABASE_SECRET_KEY")
SUPABASE_PUBLISHABLE_KEY = os.getenv("SUPABASE_PUBLISHABLE_KEY")

# ── Email / SMTP ──────────────────────────────────────────────
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", f"XSSniper <{os.getenv('SMTP_USER','')}>")

# ── App ────────────────────────────────────────────────────────
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8080")

# ── UI Theme ──────────────────────────────────────────────────
BG_PRIMARY   = '#020408'
BG_CARD      = '#0a1520'
ACCENT_GREEN = '#00ff88'
ACCENT_RED   = '#ff3b5c'
ACCENT_BLUE  = '#00d9ff'
BG_SECONDARY = '#060d12'
