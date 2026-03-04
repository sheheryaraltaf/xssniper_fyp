-- ============================================================
-- XSSniper — Supabase Schema
-- Run this once in the Supabase SQL Editor:
-- https://supabase.com/dashboard → SQL Editor → New query
-- ============================================================

-- Users table
CREATE TABLE IF NOT EXISTS public.users (
    id         BIGSERIAL PRIMARY KEY,
    username   TEXT UNIQUE NOT NULL,
    email      TEXT UNIQUE,
    password   TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Scans table
CREATE TABLE IF NOT EXISTS public.scans (
    id               BIGSERIAL PRIMARY KEY,
    date             TEXT         NOT NULL,
    url              TEXT         NOT NULL,
    status           TEXT         NOT NULL,
    vulnerabilities  INTEGER      NOT NULL DEFAULT 0,
    log_output       TEXT,
    config           TEXT,
    duration         DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Row Level Security ────────────────────────────────────────
-- The backend uses the secret key which BYPASSES RLS.
-- These policies protect direct client-side access (publishable key).

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;

-- No public access — all access is server-side via secret key only.
-- (Add policies here if you ever expose endpoints directly to the browser.)

-- ── Indexes for common queries ────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_scans_date ON public.scans (date DESC);
CREATE INDEX IF NOT EXISTS idx_users_email    ON public.users (email);
CREATE INDEX IF NOT EXISTS idx_users_username ON public.users (username);

-- ============================================================
-- Done. The application will auto-seed the admin user on
-- first startup (username: admin / password: Admin@1234).
-- ============================================================
