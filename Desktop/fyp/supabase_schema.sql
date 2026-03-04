-- ============================================================
-- XSSniper — Supabase Schema  (run once in SQL Editor)
-- https://supabase.com/dashboard/project/wlzrvbiccbulbhcuotlx/sql/new
-- ============================================================

-- ── Users ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.users (
    id         BIGSERIAL PRIMARY KEY,
    username   TEXT UNIQUE NOT NULL,
    email      TEXT UNIQUE,
    password   TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Scans ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.scans (
    id               BIGSERIAL PRIMARY KEY,
    date             TEXT             NOT NULL,
    url              TEXT             NOT NULL,
    status           TEXT             NOT NULL,
    vulnerabilities  INTEGER          NOT NULL DEFAULT 0,
    log_output       TEXT,
    config           TEXT,
    duration         DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    created_at       TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);

-- ── Password Resets ───────────────────────────────────────────
-- Stores one-time tokens for the forgot-password flow.
-- Tokens expire after 1 hour (enforced in app logic).
CREATE TABLE IF NOT EXISTS public.password_resets (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    token      TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Row Level Security ────────────────────────────────────────
-- Backend uses the secret key which bypasses RLS.
-- RLS prevents any direct browser/client access to these tables.
ALTER TABLE public.users           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.password_resets ENABLE ROW LEVEL SECURITY;

-- ── Indexes ───────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_scans_date           ON public.scans (date DESC);
CREATE INDEX IF NOT EXISTS idx_users_email          ON public.users (email);
CREATE INDEX IF NOT EXISTS idx_users_username       ON public.users (username);
CREATE INDEX IF NOT EXISTS idx_resets_token         ON public.password_resets (token);
CREATE INDEX IF NOT EXISTS idx_resets_user_id       ON public.password_resets (user_id);

-- ============================================================
-- Done! The app auto-seeds admin on first startup.
-- username: admin  |  password: Admin@1234
-- ============================================================
