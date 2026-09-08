"""CronVault — cron job management dashboard (multi-tenant).

FastAPI + PostgreSQL backend with per-company isolation and open self-signup.

Security model
--------------
- Companies are fully isolated. Every job row carries a company_id and all
  job queries are scoped to the authenticated company.
- Passwords are hashed with PBKDF2-HMAC-SHA256 (200k iters, random salt).
- Login issues an httpOnly, SameSite=Lax session cookie (no JWT in JS).
- All /api/jobs* endpoints require a valid session; the unauthenticated
  browser is redirected to a login screen by dashboard.html itself.

DB is PostgreSQL. Connection string comes from DATABASE_URL.
psycopg2 connections need a cursor for every query (no .execute() on conn).
"""
import os, time, uuid, hashlib, secrets, hmac
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pathlib import Path
from pydantic import BaseModel

try:
    import psycopg2
    import psycopg2.extras
    HAS_PG = True
except ImportError:
    HAS_PG = False

try:
    from croniter import croniter
    HAS_CRONITER = True
except ImportError:
    HAS_CRONITER = False

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://cronvault:cronvault@db:5432/cronvault",
)

SESSION_COOKIE = "cv_session"
SESSION_DAYS = 7

app = FastAPI(title="CronVault", version="0.3")


# ---------- DB ----------
def db():
    """Return a PostgreSQL connection (dict rows). Retries while the DB
    container is still starting up so the app boots cleanly."""
    import time as _t
    last = None
    for _ in range(30):
        try:
            conn = psycopg2.connect(
                DATABASE_URL, cursor_factory=psycopg2.extras.DictCursor
            )
            return conn
        except psycopg2.OperationalError as e:
            last = e
            _t.sleep(2)
    raise last


def init_db():
    conn = db()
    cur = conn.cursor()
    # --- multi-tenant tables ---
    cur.execute(
        """CREATE TABLE IF NOT EXISTS companies(
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            created_at  DOUBLE PRECISION
        )"""
    )
    cur.execute(
        """CREATE TABLE IF NOT EXISTS users(
            id            TEXT PRIMARY KEY,
            company_id    TEXT NOT NULL REFERENCES companies(id),
            full_name     TEXT NOT NULL,
            email         TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT DEFAULT 'admin',   -- admin | member
            created_at    DOUBLE PRECISION
        )"""
    )
    cur.execute(
        """CREATE TABLE IF NOT EXISTS sessions(
            token      TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL REFERENCES users(id),
            expires_at DOUBLE PRECISION
        )"""
    )
    # --- jobs (scoped to a company) ---
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS jobs(
            id          TEXT PRIMARY KEY,
            company_id  TEXT NOT NULL,
            name        TEXT NOT NULL,
            source      TEXT DEFAULT 'server',   -- server | kubernetes | docker | other
            host        TEXT DEFAULT 'localhost',-- node / cluster name
            schedule    TEXT NOT NULL,           -- cron expression
            command     TEXT DEFAULT '',
            description TEXT DEFAULT '',
            tags        TEXT DEFAULT '',
            enabled     INTEGER DEFAULT 1,
            last_run    DOUBLE PRECISION,
            next_run    DOUBLE PRECISION,
            created_at  DOUBLE PRECISION
        );
        """
    )
    # Migrate an existing (pre-multitenancy) jobs table if needed.
    cur.execute(
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS company_id TEXT DEFAULT ''"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_jobs_company ON jobs(company_id)"
    )
    conn.commit()
    conn.close()


init_db()


# ---------- auth helpers ----------
def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return f"pbkdf2_sha256$200000${salt.hex()}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, it, salt_h, hash_h = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", pw.encode(), bytes.fromhex(salt_h), int(it)
        )
        return hmac.compare_digest(dk.hex(), hash_h)
    except Exception:
        return False


def create_session(user_id: str):
    tok = secrets.token_urlsafe(32)
    exp = time.time() + SESSION_DAYS * 86400
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO sessions(token,user_id,expires_at) VALUES(%s,%s,%s)",
        (tok, user_id, exp),
    )
    conn.commit()
    conn.close()
    return tok, exp


def get_current_user(request: Request) -> dict:
    """Resolve the logged-in user from the session cookie. Raises 401."""
    tok = request.cookies.get(SESSION_COOKIE)
    if not tok:
        raise HTTPException(401, "not authenticated")
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """SELECT s.user_id, s.expires_at,
                  u.id, u.company_id, u.full_name, u.email, u.role,
                  c.name AS company_name
           FROM sessions s
           JOIN users u   ON u.id = s.user_id
           JOIN companies c ON c.id = u.company_id
           WHERE s.token = %s""",
        (tok,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(401, "invalid session")
    if row["expires_at"] < time.time():
        raise HTTPException(401, "session expired")
    return dict(row)


def set_session_cookie(response: Response, token: str):
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="lax",
        max_age=SESSION_DAYS * 86400, path="/",
    )


# ---------- page ----------
@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "dashboard.html")


# ---------- auth endpoints ----------
class Signup(BaseModel):
    company_name: str
    full_name: str
    email: str
    password: str


@app.post("/api/auth/signup")
def signup(s: Signup, response: Response):
    if not (s.company_name.strip() and s.full_name.strip()
            and s.email.strip() and s.password):
        raise HTTPException(400, "all fields are required")
    if len(s.password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    email = s.email.strip().lower()
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email=%s", (email,))
    if cur.fetchone():
        conn.close()
        raise HTTPException(409, "email already registered")
    cid = str(uuid.uuid4())[:10]
    cur.execute(
        "INSERT INTO companies(id,name,created_at) VALUES(%s,%s,%s)",
        (cid, s.company_name.strip(), time.time()),
    )
    uid = str(uuid.uuid4())[:10]
    cur.execute(
        """INSERT INTO users(id,company_id,full_name,email,password_hash,role,created_at)
           VALUES(%s,%s,%s,%s,%s,%s,%s)""",
        (uid, cid, s.full_name.strip(), email,
         hash_password(s.password), "admin", time.time()),
    )
    conn.commit()
    conn.close()
    tok, _ = create_session(uid)
    set_session_cookie(response, tok)
    return {
        "company": {"id": cid, "name": s.company_name.strip()},
        "user": {"id": uid, "full_name": s.full_name.strip(),
                 "email": email, "role": "admin"},
    }


class Login(BaseModel):
    email: str
    password: str


@app.post("/api/auth/login")
def login(l: Login, response: Response):
    email = l.email.strip().lower()
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """SELECT u.id, u.company_id, u.full_name, u.email, u.role,
                  u.password_hash, c.name AS company_name
           FROM users u JOIN companies c ON c.id = u.company_id
           WHERE u.email=%s""",
        (email,),
    )
    u = cur.fetchone()
    conn.close()
    if not u or not verify_password(l.password, u["password_hash"]):
        raise HTTPException(401, "invalid email or password")
    tok, _ = create_session(u["id"])
    set_session_cookie(response, tok)
    return {
        "company": {"id": u["company_id"], "name": u["company_name"]},
        "user": {"id": u["id"], "full_name": u["full_name"],
                 "email": u["email"], "role": u["role"]},
    }


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    tok = request.cookies.get(SESSION_COOKIE)
    if tok:
        conn = db()
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE token=%s", (tok,))
        conn.commit()
        conn.close()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
def me(request: Request):
    u = get_current_user(request)
    return {
        "user": {"id": u["id"], "full_name": u["full_name"],
                 "email": u["email"], "role": u["role"]},
        "company": {"id": u["company_id"], "name": u["company_name"]},
    }


# ---------- job helpers ----------
def compute_next(schedule: str, after: float | None = None):
    """Return next fire timestamp for a cron expr or friendly alias."""
    if not HAS_CRONITER:
        return None
    aliases = {
        "@hourly": "0 * * * *", "@daily": "0 0 * * *", "@midnight": "0 0 * * *",
        "@weekly": "0 0 * * 0", "@monthly": "0 0 1 * *", "@yearly": "0 0 1 1 *",
        "@annually": "0 0 1 1 *", "@reboot": None,
        "every minute": "* * * * *",
        "every hour": "0 * * * *",
        "every day": "0 0 * * *",
    }
    s = schedule.strip().lower()
    if s in aliases:
        schedule = aliases[s] or "* * * * *"
    else:
        import re
        m = re.fullmatch(r"every\s+(\d+)\s*(minutes?|mins?|hours?|hrs?)", s)
        if m:
            n, unit = int(m.group(1)), m.group(2)
            if n <= 0 or (unit.startswith("min") and n > 59) or (unit.startswith("h") and n > 23):
                raise HTTPException(400, f"interval out of range: {schedule}")
            schedule = f"*/{n} * * * *" if unit.startswith("min") else f"0 */{n} * * *"
    try:
        base = datetime.fromtimestamp(after or time.time(), tz=timezone.utc)
        it = croniter(schedule, base)
        return it.get_next(float)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            400,
            f"Invalid cron expression: '{schedule}'. Examples: */5 * * * * , "
            f"0 2 * * * , @daily , every 10 minutes",
        )


def sync_next(row) -> dict:
    d = dict(row)
    d["next_run"] = compute_next(d["schedule"], d["last_run"])
    return d


class Job(BaseModel):
    name: str
    schedule: str                      # cron expression e.g. "*/5 * * * *"
    source: str = "server"             # server|kubernetes|docker|other
    host: str = "localhost"
    command: str = ""
    description: str = ""
    tags: str = ""
    enabled: bool = True


@app.post("/api/jobs")
def create_job(job: Job, request: Request):
    u = get_current_user(request)
    cid = u["company_id"]
    jid = str(uuid.uuid4())[:8]
    next_run = compute_next(job.schedule)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO jobs
           (id,company_id,name,source,host,schedule,command,description,tags,enabled,last_run,next_run,created_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (jid, cid, job.name, job.source, job.host, job.schedule, job.command,
         job.description, job.tags, int(job.enabled), None, next_run, time.time()),
    )
    conn.commit(); conn.close()
    return {"id": jid, "company_id": cid, **job.model_dump(), "next_run": next_run}


@app.get("/api/jobs")
def list_jobs(request: Request):
    u = get_current_user(request)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM jobs WHERE company_id=%s ORDER BY (next_run IS NULL), next_run",
        (u["company_id"],),
    )
    rows = [sync_next(r) for r in cur.fetchall()]
    conn.close()
    return rows


@app.get("/api/jobs/{jid}")
def get_job(jid: str, request: Request):
    u = get_current_user(request)
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM jobs WHERE id=%s AND company_id=%s",
                (jid, u["company_id"]))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "not found")
    return sync_next(row)


@app.put("/api/jobs/{jid}")
def update_job(jid: str, job: Job, request: Request):
    u = get_current_user(request)
    next_run = compute_next(job.schedule)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """UPDATE jobs SET name=%s, source=%s, host=%s, schedule=%s, command=%s,
           description=%s, tags=%s, enabled=%s, next_run=%s
           WHERE id=%s AND company_id=%s""",
        (job.name, job.source, job.host, job.schedule, job.command,
         job.description, job.tags, int(job.enabled), next_run, jid,
         u["company_id"]),
    )
    conn.commit(); conn.close()
    if cur.rowcount == 0:
        raise HTTPException(404, "not found")
    return {"updated": jid, "next_run": next_run}


@app.delete("/api/jobs/{jid}")
def delete_job(jid: str, request: Request):
    u = get_current_user(request)
    conn = db()
    cur = conn.cursor()
    cur.execute("DELETE FROM jobs WHERE id=%s AND company_id=%s",
                (jid, u["company_id"]))
    conn.commit(); conn.close()
    if cur.rowcount == 0:
        raise HTTPException(404, "not found")
    return {"deleted": jid}


class Toggle(BaseModel):
    enabled: bool


@app.patch("/api/jobs/{jid}/toggle")
def toggle_job(jid: str, body: Toggle, request: Request):
    u = get_current_user(request)
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE jobs SET enabled=%s WHERE id=%s AND company_id=%s",
                (int(body.enabled), jid, u["company_id"]))
    conn.commit(); conn.close()
    if cur.rowcount == 0:
        raise HTTPException(404, "not found")
    return {"id": jid, "enabled": body.enabled}


class RunNow(BaseModel):
    status: str = "success"            # success | failed


@app.post("/api/jobs/{jid}/run")
def mark_run(jid: str, body: RunNow, request: Request):
    """Record that the job just ran (manually triggered or externally observed)."""
    u = get_current_user(request)
    now = time.time()
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM jobs WHERE id=%s AND company_id=%s",
                (jid, u["company_id"]))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "not found")
    next_run = compute_next(row["schedule"], now)
    cur.execute("UPDATE jobs SET last_run=%s, next_run=%s WHERE id=%s AND company_id=%s",
                (now, next_run, jid, u["company_id"]))
    conn.commit(); conn.close()
    return {"id": jid, "last_run": now, "next_run": next_run}
