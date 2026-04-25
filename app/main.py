import os
from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from secrets import token_urlsafe

from .db import (
    create_phase,
    ensure_seed_users,
    get_conn,
    get_current_phase,
    get_latest_phase,
    get_targets,
    hash_password,
    init_db,
    get_owner_latest_job,
    get_owner_defense_prompt,
    get_owner_flag,
    enqueue_llm_job,
    utcnow_iso,
)
from .loadenv import load_env
load_env()

MAX_PROMPT = int(os.getenv("MAX_PROMPT", "1000"))
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "60"))
SESSION_SECRET = os.getenv("SESSION_SECRET", "change-this-in-production")

app = FastAPI(title="LLM CTF Attack & Defense")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
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
def defense_edit(request: Request, prompt_body: str = Form(default="")):
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
        last_defense_prompt = get_owner_defense_prompt(conn, phase["id"], user["id"])

    return templates.TemplateResponse(
        request=request,
        name="defense_test.html",
        context={
            "user": user, "phase": phase,
            "last_defense_prompt": last_defense_prompt,
        }
    )


@app.post("/defense/test", response_class=HTMLResponse)
def defense_test(request: Request, attack_prompt: str = Form(default=""), defense_prompt: str = Form(default="")):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user

    with get_conn() as conn:
        phase = get_current_phase(conn)
        if not phase or phase["state"] != "defense":
            return RedirectResponse("/dashboard", status_code=303)
        if len(defense_prompt) > MAX_PROMPT:
            return templates.TemplateResponse(
                request=request,
                name="defense_test.html",
                context={
                    "user": user,
                    "phase": phase,
                    "last_defense_prompt": defense_prompt,
                    "last_attack_prompt": attack_prompt,
                    "error": f"Defense prompt is too long (max {MAX_PROMPT} chars).",
                },
            )
        if len(attack_prompt) == 0:
            return templates.TemplateResponse(
                request=request,
                name="defense_test.html",
                context={
                    "user": user,
                    "phase": phase,
                    "last_defense_prompt": defense_prompt,
                    "last_attack_prompt": attack_prompt,
                    "error": f"Attack prompt cannot be empty.",
                },
            )
        if len(attack_prompt) > MAX_PROMPT:
            return templates.TemplateResponse(
                request=request,
                name="defense_test.html",
                context={
                    "user": user,
                    "phase": phase,
                    "last_defense_prompt": defense_prompt,
                    "last_attack_prompt": attack_prompt,
                    "error": f"Attack prompt is too long (max {MAX_PROMPT} chars).",
                },
            )
        latest_job = get_owner_latest_job(conn, phase["id"], "test", user["id"])
        if latest_job and latest_job["status"] in ("pending", "running"):
            return templates.TemplateResponse(
                request=request,
                name="defense_test.html",
                context={
                    "user": user,
                    "phase": phase,
                    "last_defense_prompt": defense_prompt,
                    "last_attack_prompt": attack_prompt,
                    "error": f"You have a pending/running job (ID: {latest_job['id']}). Please wait for it to finish before submitting a new test.",
                },
            )

        # rate limit
        if latest_job and latest_job["created_at"] > utcnow_iso(negative_seconds=RATE_LIMIT):
            return templates.TemplateResponse(
                request=request,
                name="defense_test.html",
                context={
                    "user": user,
                    "phase": phase,
                    "last_defense_prompt": defense_prompt,
                    "last_attack_prompt": attack_prompt,
                    "error": f"Rate Limit (1 min).",
                },
            )

        job_id = enqueue_llm_job(
            conn,
            phase_id=phase["id"],
            kind="test",
            defense_user_id=user["id"],
            attack_user_id=user["id"],
            defense_prompt=defense_prompt,
            attack_prompt=attack_prompt,
        )

    return templates.TemplateResponse(
        request=request,
        name="defense_test.html",
        context={
            "user": user,
            "phase": phase,
            "last_defense_prompt": defense_prompt,
            "last_attack_prompt": attack_prompt,
            "job_id": job_id,
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
    request: Request, target_user_id: int = Form(...), attack_prompt: str = Form(default="")
):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user

    with get_conn() as conn:
        phase = get_current_phase(conn)
        if not phase or phase["state"] != "attack":
            return RedirectResponse("/dashboard", status_code=303)
        
        targets = get_targets(conn, user["id"])
        # validate target user
        target_user = conn.execute(
            "SELECT id, username FROM users WHERE id = ? AND is_admin = 0",
            (target_user_id,),
        ).fetchone()
        if not target_user:
            return templates.TemplateResponse(
                request=request,
                name="attack.html",
                context={
                    "user": user,
                    "phase": phase,
                    "targets": targets,
                    "last_attack_prompt": attack_prompt,
                    "error": f"Target not found.",
                },
            )
        if target_user["id"] == user["id"]:
            return templates.TemplateResponse(
                request=request,
                name="attack.html",
                context={
                    "user": user,
                    "phase": phase,
                    "targets": targets,
                    "last_attack_prompt": attack_prompt,
                    "error": f"You cannot attack yourself.",
                },
            )

        latest_job = get_owner_latest_job(conn, phase["id"], "attack", user["id"])
        if latest_job and latest_job["status"] in ("pending", "running"):
            return templates.TemplateResponse(
                request=request,
                name="attack.html",
                context={
                    "user": user,
                    "phase": phase,
                    "targets": targets,
                    "last_attack_prompt": attack_prompt,
                    "error": f"You have a pending/running job (ID: {latest_job['id']}). Please wait for it to finish before submitting a new attack.",
                },
            )
        # rate limit
        if latest_job and latest_job["created_at"] > utcnow_iso(negative_seconds=RATE_LIMIT):
            return templates.TemplateResponse(
                request=request,
                name="attack.html",
                context={
                    "user": user,
                    "phase": phase,
                    "targets": targets,
                    "last_attack_prompt": attack_prompt,
                    "error": f"Rate Limit (1 min).",
                },
            )

        defense_prompt = get_owner_defense_prompt(conn, phase["id"], target_user_id)
        job_id = enqueue_llm_job(
            conn,
            phase_id=phase["id"],
            kind="attack",
            defense_user_id=target_user_id,
            attack_user_id=user["id"],
            defense_prompt=defense_prompt,
            attack_prompt=attack_prompt,
        )


    return templates.TemplateResponse(
        request=request,
        name="attack.html",
        context={
            "user": user,
            "phase": phase,
            "targets": targets,
            "last_attack_prompt": attack_prompt,
            "job_id": job_id,
        },
    )


@app.get("/review", response_class=HTMLResponse)
def review_page(request: Request):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user

    with get_conn() as conn:
        phase = get_latest_phase(conn)
        if not phase:
            return RedirectResponse("/dashboard", status_code=303)
        """
        Take care of visibility.
        ## Defense phase
        - Admin: can see all information of test queries (defense prompts, attack prompts, results)
        - User: can see only their own test queries (defense prompts, attack prompts, results)
        ## Attack/Frozen phase
        - Admin: can see all information of attack queries (defense prompts, attack prompts, results)
        - User:
            - their own attack queries (attack prompts, results)
            - their own test queries (defense prompts, attack prompts, results)
        ## Closed phase
        - Admin: can see all information of test & attack queries (defense prompts, attack prompts, results)
        - User: can see all information of attack queries (defense prompts, attack prompts, results)
        """
        if user["is_admin"]:
            # Admin can see everything
            submissions = conn.execute(
                """
                SELECT a.id, p.round_no, a.kind, a.created_at, au.username AS attack_user_name, du.username AS defense_user_name, a.status
                FROM llm_jobs a
                JOIN phases p ON p.id = a.phase_id
                JOIN users au ON au.id = a.attack_user_id
                JOIN users du ON du.id = a.defense_user_id
                ORDER BY a.id
                """
            ).fetchall()
        else:
            submissions = conn.execute(
                """
                SELECT a.id, p.round_no, a.kind, a.created_at, au.username AS attack_user_name, du.username AS defense_user_name, a.status
                FROM llm_jobs a
                JOIN phases p ON p.id = a.phase_id
                JOIN users au ON au.id = a.attack_user_id
                JOIN users du ON du.id = a.defense_user_id
                WHERE ( p.state = 'defense' AND a.kind = 'test' AND a.attack_user_id = ? )
                    OR ( p.state = 'attack' AND a.kind = 'attack' AND a.attack_user_id = ? )
                        OR ( p.state = 'attack' AND a.kind = 'test' AND a.attack_user_id = ? )
                    OR ( p.state = 'frozen' AND a.kind = 'attack' AND a.attack_user_id = ? )
                        OR ( p.state = 'frozen' AND a.kind = 'test' AND a.attack_user_id = ? )
                    OR ( p.state = 'closed' AND a.kind = 'attack' )
                ORDER BY a.id
                """,
                (user["id"], user["id"], user["id"], user["id"], user["id"]),
            ).fetchall()

    return templates.TemplateResponse(
        request=request,
        name="review.html",
        context={"user": user, "phase": phase, "submissions": submissions[::-1]},
    )


@app.get("/submission/{job_id}", response_class=HTMLResponse)
def submission_page(request: Request, job_id: int):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user

    with get_conn() as conn:
        phase = get_latest_phase(conn)
        if not phase:
            return RedirectResponse("/dashboard", status_code=303)
        """
        Take care of visibility.
        ## Defense phase
        - Admin: can see all information of test queries (defense prompts, attack prompts, results)
        - User: can see only their own test queries (defense prompts, attack prompts, results)
        ## Attack/Frozen phase
        - Admin: can see all information of attack queries (defense prompts, attack prompts, results)
        - User:
            - their own attack queries (attack prompts, results)
            - their own test queries (defense prompts, attack prompts, results)
        ## Closed phase
        - Admin: can see all information of test & attack queries (defense prompts, attack prompts, results)
        - User: can see all information of attack queries (defense prompts, attack prompts, results)
        ## Error submission
        Only admin can see error details.
        """
        submission = conn.execute(
            """
            SELECT a.id, p.round_no, p.state, a.kind, a.created_at, a.evaluation_started_at, a.evaluation_finished_at,
                   a.attack_user_id, a.defense_user_id,
                   au.username AS attack_user_name, du.username AS defense_user_name,
                   a.defense_prompt, a.attack_prompt,
                   a.result, a.error, a.error_details, a.status
            FROM llm_jobs a
            JOIN phases p ON p.id = a.phase_id
            JOIN users au ON au.id = a.attack_user_id
            JOIN users du ON du.id = a.defense_user_id
            WHERE a.id = ?
            """, (job_id,)
        ).fetchone()

    if not submission:
        return templates.TemplateResponse(
            request=request,
            name="submission.html",
            context={"user": user, "phase": phase, "job_id": job_id, "error": "Submission not found."},
        )
    submission = dict(submission)
    if not user["is_admin"]:
        del submission["error_details"]  # Hide error details for non-admins
        pass_check = False
        if submission["state"] == "defense":
            if submission["kind"] == "test" and submission["attack_user_id"] == user["id"]:
                pass_check = True
        elif submission["state"] == "attack":
            if submission["kind"] == "test" and submission["attack_user_id"] == user["id"]:
                pass_check = True
            if submission["kind"] == "attack" and submission["attack_user_id"] == user["id"]:
                pass_check = True
                # Hide defense prompt for attack phase users
                submission["defense_prompt"] = "[Hidden until the phase is closed]"
        elif submission["state"] == "frozen":
            if submission["kind"] == "test" and submission["attack_user_id"] == user["id"]:
                pass_check = True
            if submission["kind"] == "attack" and submission["attack_user_id"] == user["id"]:
                pass_check = True
                # Hide defense prompt for frozen phase users
                submission["defense_prompt"] = "[Hidden until the phase is closed]"
        elif submission["state"] == "closed":
            if submission["kind"] == "attack":
                pass_check = True
        if not pass_check:
            return templates.TemplateResponse(
                request=request,
                name="submission.html",
                context={"user": user, "phase": phase, "job_id": job_id, "error": "You don't have permission to view this submission."},
            )

    return templates.TemplateResponse(
        request=request,
        name="submission.html",
        context={"user": user, "phase": phase, "job_id": job_id, "submission": submission},
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

@app.post("/admin/phase/freeze")
def admin_freeze_phase(request: Request):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user
    if not user["is_admin"]:
        return RedirectResponse("/dashboard", status_code=303)

    with get_conn() as conn:
        phase = get_current_phase(conn)
        if phase:
            conn.execute(
                "UPDATE phases SET state = 'frozen', ended_at = ? WHERE id = ?",
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
                "UPDATE phases SET state = 'closed' WHERE id = ?",
                (phase["id"],),
            )

    return RedirectResponse("/admin", status_code=303)

@app.get("/admin_users", response_class=HTMLResponse)
def admin_users_page(request: Request):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user
    if not user["is_admin"]:
        return RedirectResponse("/dashboard", status_code=303)

    with get_conn() as conn:
        phase = get_current_phase(conn)
        flags = conn.execute(
            """
            SELECT f.id, f.flag_value, u.username, p.round_no
            FROM flags f
            JOIN users u ON u.id = f.owner_user_id
            JOIN phases p ON p.id = f.phase_id
            ORDER BY f.id
            """
        ).fetchall()
        users = conn.execute("SELECT * FROM users WHERE is_admin = 0").fetchall()
    if not flags:
        flags = []

    flags = [dict(f) for f in flags]
    return templates.TemplateResponse(
        request=request,
        name="admin_users.html",
        context={"user": user, "flags": flags, "phase": phase, "users": users}
    )

@app.post("/admin_users")
def admin_reset_password(request: Request, reset: int = Form(...)):
    user = require_login(request)
    if isinstance(user, RedirectResponse):
        return user
    if not user["is_admin"]:
        return RedirectResponse("/dashboard", status_code=303)

    with get_conn() as conn:
        phase = get_current_phase(conn)
        users = conn.execute("SELECT * FROM users WHERE is_admin = 0").fetchall()
        users = [dict(u) for u in users]
        for u in users:
            if reset == -1 or u["id"] == reset:
                # random pass
                new_password = token_urlsafe(16)
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (hash_password(new_password), u["id"]),
                )
                u["password"] = new_password  # Add the new password to the user dict for display

    with get_conn() as conn:
        flags = conn.execute(
            """
            SELECT f.id, f.flag_value, u.username, p.round_no
            FROM flags f
            JOIN users u ON u.id = f.owner_user_id
            JOIN phases p ON p.id = f.phase_id
            ORDER BY f.id
            """
        ).fetchall()
    if not flags:
        flags = []

    flags = [dict(f) for f in flags]
    return templates.TemplateResponse(
        request=request,
        name="admin_users.html",
        context={"user": user, "users": users, "flags": flags, "phase": phase, "reset_event": True}
    )

