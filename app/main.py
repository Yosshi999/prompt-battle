import os
from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .db import (
    create_phase,
    ensure_seed_users,
    get_conn,
    get_current_phase,
    hash_password,
    init_db,
    render_full_system_prompt,
    get_owner_flag,
    utcnow_iso,
)
from .llm import run_chat

MAX_PROMPT = int(os.getenv("MAX_PROMPT", "1000"))

app = FastAPI(title="LLM CTF Attack & Defense")
app.add_middleware(SessionMiddleware, secret_key="change-this-in-production2")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


@app.on_event("startup")
def startup_event():
    init_db()
    ensure_seed_users()


def current_user(request: Request) -> Optional[dict]:
    uid = request.session.get("user_id")
    if not uid:
        return None
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        return dict(row) if row else None


def require_login(request: Request):
    user = current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return user


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if current_user(request):
        return RedirectResponse("/dashboard", status_code=303)
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={"error": None})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    with get_conn() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not user or user["password_hash"] != hash_password(password):
            return templates.TemplateResponse(
                request=request, name="login.html", context={"error": "Invalid credentials"}
            )

        request.session["user_id"] = user["id"]
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user

    with get_conn() as conn:
        phase = get_current_phase(conn)
        flag = get_owner_flag(conn, phase["id"], user["id"]) if phase else None

    return templates.TemplateResponse(
        request=request, name="dashboard.html", context={"user": user, "phase": phase, "flag": flag}
    )


@app.get("/defense/edit", response_class=HTMLResponse)
def defense_edit_page(request: Request):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user

    with get_conn() as conn:
        phase = get_current_phase(conn)
        if not phase or phase["state"] != "defense":
            return RedirectResponse("/dashboard", status_code=303)
        row = conn.execute(
            "SELECT prompt_body FROM system_prompts WHERE phase_id = ? AND owner_user_id = ?",
            (phase["id"], user["id"]),
        ).fetchone()

    return templates.TemplateResponse(
        request=request,
        name="defense_edit.html",
        context={
            "user": user,
            "phase": phase,
            "prompt_body": row["prompt_body"] if row else "",
        },
    )


@app.post("/defense/edit")
def defense_edit(request: Request, prompt_body: str = Form(...)):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user

    with get_conn() as conn:
        phase = get_current_phase(conn)
        if not phase or phase["state"] != "defense":
            return RedirectResponse("/dashboard", status_code=303)
        row = conn.execute(
            "SELECT prompt_body FROM system_prompts WHERE phase_id = ? AND owner_user_id = ?",
            (phase["id"], user["id"]),
        ).fetchone()
        current_prompt: str = row["prompt_body"] if row else ""
        if len(prompt_body) > MAX_PROMPT:
            return templates.TemplateResponse(
                request=request,
                name="defense_edit.html",
                context={
                    "user": user,
                    "phase": phase,
                    "prompt_body": prompt_body,
                    "error": f"Prompt is too long (max {MAX_PROMPT} chars).",
                },
            )
        if prompt_body == current_prompt:
            return templates.TemplateResponse(
                request=request,
                name="defense_edit.html",
                context={
                    "user": user,
                    "phase": phase,
                    "prompt_body": prompt_body,
                    "error": f"Prompt is same as the previous one.",
                },
            )
        conn.execute(
            """
            UPDATE system_prompts
            SET prompt_body = ?, updated_at = ?
            WHERE phase_id = ? AND owner_user_id = ?
            """,
            (prompt_body, utcnow_iso(), phase["id"], user["id"]),
        )

    return templates.TemplateResponse(
        request=request,
        name="defense_edit.html",
        context={
            "user": user,
            "phase": phase,
            "prompt_body": prompt_body,
            "ok": f"Prompt saved successfully ({len(prompt_body)} / {MAX_PROMPT} chars).",
        },
    )


@app.get("/defense/test", response_class=HTMLResponse)
def defense_test_page(request: Request):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user

    with get_conn() as conn:
        phase = get_current_phase(conn)
        if not phase or phase["state"] != "defense":
            return RedirectResponse("/dashboard", status_code=303)

    return templates.TemplateResponse(
        request=request, name="defense_test.html", context={"user": user, "phase": phase, "result": None}
    )


@app.post("/defense/test", response_class=HTMLResponse)
def defense_test(request: Request, user_prompt: str = Form(...)):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user

    with get_conn() as conn:
        phase = get_current_phase(conn)
        if not phase or phase["state"] != "defense":
            return RedirectResponse("/dashboard", status_code=303)

        full_system_prompt = render_full_system_prompt(conn, phase["id"], user["id"])
        response_text = run_chat(full_system_prompt, user_prompt)

        conn.execute(
            """
            INSERT INTO defense_tests (phase_id, user_id, user_prompt, response_text, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (phase["id"], user["id"], user_prompt, response_text, utcnow_iso()),
        )

    return templates.TemplateResponse(
        request=request,
        name="defense_test.html",
        context={
            "user": user,
            "phase": phase,
            "result": response_text,
            "last_prompt": user_prompt,
        },
    )


@app.get("/attack", response_class=HTMLResponse)
def attack_page(request: Request):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user

    with get_conn() as conn:
        phase = get_current_phase(conn)
        if not phase or phase["state"] != "attack":
            return RedirectResponse("/dashboard", status_code=303)
        targets = conn.execute(
            "SELECT id, username FROM users WHERE is_admin = 0 AND id != ? ORDER BY id",
            (user["id"],),
        ).fetchall()

    return templates.TemplateResponse(
        request=request,
        name="attack.html",
        context={"user": user, "phase": phase, "targets": targets, "result": None},
    )


@app.post("/attack")
def attack_submit(
    request: Request, target_user_id: int = Form(...), user_prompt: str = Form(...)
):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user

    with get_conn() as conn:
        phase = get_current_phase(conn)
        if not phase or phase["state"] != "attack":
            return RedirectResponse("/dashboard", status_code=303)

        full_system_prompt = render_full_system_prompt(conn, phase["id"], target_user_id)
        response_text = run_chat(full_system_prompt, user_prompt)

        conn.execute(
            """
            INSERT INTO attacks (phase_id, attacker_user_id, target_user_id, user_prompt, response_text, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (phase["id"], user["id"], target_user_id, user_prompt, response_text, utcnow_iso()),
        )

        targets = conn.execute(
            "SELECT id, username FROM users WHERE is_admin = 0 AND id != ? ORDER BY id",
            (user["id"],),
        ).fetchall()

    return templates.TemplateResponse(
        request=request,
        name="attack.html",
        context={
            "user": user,
            "phase": phase,
            "targets": targets,
            "result": response_text,
            "last_prompt": user_prompt,
            "target_user_id": target_user_id,
        },
    )


@app.get("/review/{phase_id}", response_class=HTMLResponse)
def review_page(request: Request, phase_id: int):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user

    with get_conn() as conn:
        phase = conn.execute("SELECT * FROM phases WHERE id = ?", (phase_id,)).fetchone()
        prompts = conn.execute(
            """
            SELECT u.username, s.prompt_body, s.updated_at
            FROM system_prompts s
            JOIN users u ON u.id = s.owner_user_id
            WHERE s.phase_id = ?
            ORDER BY u.id
            """,
            (phase_id,),
        ).fetchall()
        attacks = conn.execute(
            """
            SELECT a.created_at, au.username AS attacker, tu.username AS target, a.user_prompt, a.response_text
            FROM attacks a
            JOIN users au ON au.id = a.attacker_user_id
            JOIN users tu ON tu.id = a.target_user_id
            WHERE a.phase_id = ?
            ORDER BY a.id
            """,
            (phase_id,),
        ).fetchall()

    return templates.TemplateResponse(
        request=request,
        name="review.html",
        context={"user": user, "phase": phase, "prompts": prompts, "attacks": attacks},
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user
    if not user["is_admin"]:
        return RedirectResponse("/dashboard", status_code=303)

    with get_conn() as conn:
        current = get_current_phase(conn)
        latest = conn.execute("SELECT * FROM phases ORDER BY id DESC LIMIT 5").fetchall()

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={"user": user, "phase": current, "current": current, "latest": latest}
    )


@app.post("/admin/phase/new")
def admin_new_phase(request: Request):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user
    if not user["is_admin"]:
        return RedirectResponse("/dashboard", status_code=303)

    with get_conn() as conn:
        max_round = conn.execute("SELECT COALESCE(MAX(round_no), 0) AS m FROM phases").fetchone()["m"]

    create_phase(max_round + 1)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/phase/to-attack")
def admin_to_attack(request: Request):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user
    if not user["is_admin"]:
        return RedirectResponse("/dashboard", status_code=303)

    with get_conn() as conn:
        phase = get_current_phase(conn)
        if phase and phase["state"] == "defense":
            conn.execute(
                "UPDATE phases SET state = 'attack', attack_started_at = ? WHERE id = ?",
                (utcnow_iso(), phase["id"]),
            )

    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/phase/close")
def admin_close_phase(request: Request):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user
    if not user["is_admin"]:
        return RedirectResponse("/dashboard", status_code=303)

    with get_conn() as conn:
        phase = get_current_phase(conn)
        if phase:
            conn.execute(
                "UPDATE phases SET state = 'closed', ended_at = ? WHERE id = ?",
                (utcnow_iso(), phase["id"]),
            )

    return RedirectResponse("/admin", status_code=303)
