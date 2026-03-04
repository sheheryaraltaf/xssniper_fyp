#!/usr/bin/env python3
"""
XSSniper - ML-Enhanced XSS Vulnerability Scanner
FastAPI Backend Server
"""

import sys
import os
import json
import asyncio
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from backend.database import init_database, get_stats, get_history, get_scan_detail, save_scan
from backend.auth import AuthManager
from backend.scanner import ScannerManager
from backend.github_auth import get_github_login_url, exchange_code_for_token, get_github_user, get_or_create_github_user
from backend.google_auth import get_google_login_url, exchange_google_code, get_google_user, get_or_create_google_user

app = FastAPI(title="XSSniper")
app.add_middleware(SessionMiddleware, secret_key="fyp_xssniper_2025_secret")
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")
templates = Jinja2Templates(directory="frontend/templates")

scanner = ScannerManager()
active_scans = {}  # scan_id -> log lines

# ── Auth helpers ──────────────────────────────────────────────────────────────

def get_session_user(request: Request):
    return request.session.get("user")

def require_auth(request: Request):
    user = get_session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

# ── Page Routes ───────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = get_session_user(request)
    if not user:
        return RedirectResponse("/login")
    stats = get_stats()
    history = get_history()[:5]
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "user": user, "stats": stats, "history": history
    })

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if get_session_user(request):
        return RedirectResponse("/")
    github_url = get_github_login_url()
    google_url = get_google_login_url()
    return templates.TemplateResponse("login.html", {"request": request, "github_url": github_url, "google_url": google_url})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    if get_session_user(request):
        return RedirectResponse("/")
    github_url = get_github_login_url()
    google_url = get_google_login_url()
    return templates.TemplateResponse("register.html", {"request": request, "github_url": github_url, "google_url": google_url})

@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    user = get_session_user(request)
    if not user:
        return RedirectResponse("/login")
    return templates.TemplateResponse("scan.html", {"request": request, "user": user})

@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    user = get_session_user(request)
    if not user:
        return RedirectResponse("/login")
    history = get_history()
    return templates.TemplateResponse("history.html", {"request": request, "user": user, "history": history})

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    user = get_session_user(request)
    if not user:
        return RedirectResponse("/login")
    return templates.TemplateResponse("settings.html", {"request": request, "user": user})

@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    user = get_session_user(request)
    if not user:
        return RedirectResponse("/login")
    if user.get("role") != "admin":
        return RedirectResponse("/")
    users = AuthManager.get_all_users()
    return templates.TemplateResponse("admin.html", {"request": request, "user": user, "users": users})

# ── Auth API ──────────────────────────────────────────────────────────────────

class LoginForm(BaseModel):
    login: str
    password: str

class RegisterForm(BaseModel):
    username: str
    email: str
    password: str
    confirm: str

@app.post("/api/login")
async def api_login(form: LoginForm, request: Request):
    user_data = AuthManager.authenticate(form.login, form.password)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    request.session["user"] = user_data
    return {"success": True, "user": user_data}

@app.post("/api/register")
async def api_register(form: RegisterForm, request: Request):
    from backend.auth import is_valid_email
    if len(form.username) < 3:
        raise HTTPException(400, "Username must be at least 3 characters")
    if not is_valid_email(form.email):
        raise HTTPException(400, "Invalid email address")
    from backend.auth import password_meets_requirements
    pw_ok, pw_err = password_meets_requirements(form.password)
    if not pw_ok:
        raise HTTPException(400, pw_err)
    if form.password != form.confirm:
        raise HTTPException(400, "Passwords do not match")
    if AuthManager.username_exists(form.username):
        raise HTTPException(400, "Username already taken")
    if AuthManager.email_exists(form.email):
        raise HTTPException(400, "Email already registered")
    if AuthManager.register_user(form.username, form.email, form.password):
        return {"success": True}
    raise HTTPException(500, "Registration failed")


@app.get("/auth/google/callback")
async def google_callback(request: Request, code: str = "", error: str = ""):
    if error or not code:
        return RedirectResponse("/login?error=google_cancelled")
    try:
        token = await exchange_google_code(code)
        if not token:
            return RedirectResponse("/login?error=google_token_failed")
        guser = await get_google_user(token)
        if not guser:
            return RedirectResponse("/login?error=google_profile_failed")
        if not guser.get("email_verified", True):
            return RedirectResponse("/login?error=google_email_not_verified")
        user_data = get_or_create_google_user(guser)
        request.session["user"] = user_data
        return RedirectResponse("/")
    except Exception:
        return RedirectResponse("/login?error=google_error")

@app.get("/api/logout")
async def api_logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")

@app.get("/auth/github/callback")
async def github_callback(request: Request, code: str = "", error: str = ""):
    if error or not code:
        return RedirectResponse("/login?error=github_cancelled")
    try:
        token = await exchange_code_for_token(code)
        if not token:
            return RedirectResponse("/login?error=token_failed")
        github_user = await get_github_user(token)
        if not github_user:
            return RedirectResponse("/login?error=profile_failed")
        user_data = get_or_create_github_user(github_user)
        request.session["user"] = user_data
        return RedirectResponse("/")
    except Exception as e:
        return RedirectResponse(f"/login?error={str(e)}")

# ── Scan API ──────────────────────────────────────────────────────────────────

class ScanConfig(BaseModel):
    url: str
    data: str = ""
    json_mode: bool = False
    crawl: bool = False
    level: int = 2
    threads: int = 2
    timeout: int = 5
    delay: float = 0
    fuzzer: bool = False
    encode: bool = False
    path: bool = False
    file: str = ""
    skip_dom: bool = False
    headers: str = ""
    proxy: str = ""
    ml_prefilter: bool = False

@app.post("/api/scan/start")
async def start_scan(config: ScanConfig, request: Request):
    user = require_auth(request)
    scan_id = datetime.now().strftime("%Y%m%d%H%M%S")
    active_scans[scan_id] = {"logs": [], "done": False, "result": None}

    async def run():
        logs = active_scans[scan_id]["logs"]
        async def log_cb(msg):
            logs.append(msg)
        result = await scanner.run_scan(config.dict(), log_cb)
        active_scans[scan_id]["done"] = True
        active_scans[scan_id]["result"] = result

    asyncio.create_task(run())
    return {"scan_id": scan_id}

@app.get("/api/scan/{scan_id}/stream")
async def stream_logs(scan_id: str, request: Request):
    require_auth(request)

    async def event_generator():
        last_idx = 0
        while True:
            if scan_id not in active_scans:
                yield f"data: ERROR: Scan not found\n\n"
                break
            scan = active_scans[scan_id]
            logs = scan["logs"]
            while last_idx < len(logs):
                yield f"data: {logs[last_idx]}\n\n"
                last_idx += 1
            if scan["done"]:
                result = scan.get("result", {})
                yield f"data: __DONE__{json.dumps(result)}\n\n"
                break
            await asyncio.sleep(0.1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.post("/api/scan/stop")
async def stop_scan(request: Request):
    require_auth(request)
    scanner.stop_scan()
    return {"success": True}

# ── Data API ──────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def api_stats(request: Request):
    require_auth(request)
    return get_stats()

@app.get("/api/history")
async def api_history(request: Request):
    require_auth(request)
    return get_history()

@app.get("/api/scan-detail/{scan_id}")
async def api_scan_detail(scan_id: int, request: Request):
    require_auth(request)
    d = get_scan_detail(scan_id)
    if not d:
        raise HTTPException(404, "Scan not found")
    return d

@app.get("/api/export/csv/{scan_id}")
async def export_csv(scan_id: int, request: Request):
    require_auth(request)
    import csv, io
    d = get_scan_detail(scan_id)
    if not d:
        raise HTTPException(404, "Scan not found")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Field", "Value"])
    writer.writerow(["Scan ID", d["id"]])
    writer.writerow(["Date", d["date"]])
    writer.writerow(["URL", d["url"]])
    writer.writerow(["Status", d["status"]])
    writer.writerow(["Vulnerabilities", d["vulnerabilities"]])
    writer.writerow(["Duration", d["duration"]])
    writer.writerow([])
    writer.writerow(["--- Scan Log ---"])
    for line in (d["log_output"] or "").split("\n"):
        if line.strip():
            writer.writerow([line])
    output.seek(0)
    return Response(content=output.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"})

@app.delete("/api/admin/users/{user_id}")
async def delete_user(user_id: int, request: Request):
    user = require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin only")
    if AuthManager.delete_user(user_id):
        return {"success": True}
    raise HTTPException(400, "Cannot delete this user")

if __name__ == "__main__":
    import uvicorn
    init_database()
    uvicorn.run(app, host="0.0.0.0", port=8080, reload=False)
