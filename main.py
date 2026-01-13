# main.py
import os
import sqlite3
from datetime import date, datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator

# ---------------------------
# Config
# ---------------------------
DB_PATH = os.getenv("DB_PATH", "licenses.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "CHANGE_THIS_TOKEN")
ALLOW_ORIGINS = os.getenv("ALLOW_ORIGINS", "*")  # ex: "https://meusite.com" ou "*" para dev

# ---------------------------
# App
# ---------------------------
app = FastAPI(title="License Server", version="1.1")

# CORS - dev friendly; em produção restringe ALLOW_ORIGINS adequadamente
origins = [o.strip() for o in ALLOW_ORIGINS.split(",")] if ALLOW_ORIGINS != "*" else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# DB helpers
# ---------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            active INTEGER,
            expiration TEXT,
            single_machine INTEGER,
            bound_device_id TEXT,
            client TEXT,
            created_at TEXT
        )
    """)
    db.commit()
    db.close()

def row_to_dict(row):
    if row is None:
        return None
    return {k: row[k] for k in row.keys()}

# init on startup
@app.on_event("startup")
def startup():
    init_db()

# ---------------------------
# Models
# ---------------------------
class CreateLicenseRequest(BaseModel):
    key: Optional[str] = None
    client: Optional[str] = None
    expiration: Optional[str] = None  # YYYY-MM-DD or None
    single_machine: bool = True
    active: bool = True

    @validator("expiration")
    def validate_expiration(cls, v):
        if not v:
            return None
        try:
            date.fromisoformat(v)
        except Exception:
            raise ValueError("expiration deve estar no formato YYYY-MM-DD")
        return v

class LicenseRequest(BaseModel):
    key: str
    device_id: str

class AdminKeyRequest(BaseModel):
    key: str

class ExtendRequest(BaseModel):
    key: str
    extra_days: int

# ---------------------------
# Admin dependency
# ---------------------------
def require_admin(x_admin_token: Optional[str] = Header(None)):
    if ADMIN_TOKEN is None or ADMIN_TOKEN == "":
        raise HTTPException(status_code=500, detail="ADMIN_TOKEN não configurado no servidor")
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

# ---------------------------
# Util
# ---------------------------
import secrets
def generate_key():
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    parts = []
    for _ in range(4):
        parts.append("".join(secrets.choice(chars) for _ in range(5)))
    return "-".join(parts)

# ---------------------------
# Endpoints públicos
# ---------------------------
@app.get("/")
def root():
    return {"status": "ok", "version": "1.1"}

@app.post("/create")
def create_license(req: CreateLicenseRequest, allowed: bool = Depends(require_admin)):
    key = req.key.strip() if req.key else generate_key()
    expiration = req.expiration if req.expiration else None

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            """
            INSERT INTO licenses (key, active, expiration, single_machine, bound_device_id, client, created_at)
            VALUES (?, ?, ?, ?, NULL, ?, ?)
            """,
            (key, 1 if req.active else 0, expiration, 1 if req.single_machine else 0, req.client, datetime.utcnow().isoformat())
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        raise HTTPException(status_code=400, detail="Key já existe")
    db.close()
    return {"key": key, "created": True}

@app.post("/activate")
def activate_license(data: LicenseRequest):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM licenses WHERE key = ?", (data.key,))
    row = cur.fetchone()
    if not row:
        db.close()
        raise HTTPException(status_code=404, detail="Key inexistente")

    if row["active"] != 1:
        db.close()
        raise HTTPException(status_code=403, detail="Key revogada")

    if row["expiration"]:
        if date.today() > date.fromisoformat(row["expiration"]):
            db.close()
            raise HTTPException(status_code=403, detail="Key expirada")

    if row["single_machine"] == 1:
        if row["bound_device_id"] is None:
            cur.execute("UPDATE licenses SET bound_device_id = ? WHERE key = ?", (data.device_id, data.key))
            db.commit()
            db.close()
            return {"status": "ok", "message": "ativada e vinculada ao device"}
        elif row["bound_device_id"] != data.device_id:
            db.close()
            raise HTTPException(status_code=403, detail="Key já usada em outro dispositivo")

    db.close()
    return {"status": "ok", "message": "ativação confirmada"}

@app.post("/validate")
def validate_license(data: LicenseRequest):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM licenses WHERE key = ?", (data.key,))
    row = cur.fetchone()
    if not row:
        db.close()
        return {"valid": False}

    if row["active"] != 1:
        db.close()
        return {"valid": False}

    if row["expiration"] and date.today() > date.fromisoformat(row["expiration"]):
        db.close()
        return {"valid": False}

    if row["single_machine"] == 1 and row["bound_device_id"] is not None and row["bound_device_id"] != data.device_id:
        db.close()
        return {"valid": False}

    db.close()
    return {"valid": True, "expires_at": row["expiration"]}

# ---------------------------
# Admin endpoints (quality of life)
# ---------------------------
@app.get("/admin/list")
def admin_list(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    q_client: Optional[str] = Query(None),
    only_active: Optional[int] = Query(None),
    admin: bool = Depends(require_admin)
):
    offset = (page - 1) * per_page
    db = get_db()
    cur = db.cursor()

    base_query = "SELECT key, active, expiration, single_machine, bound_device_id, client, created_at FROM licenses"
    params = []
    filters = []
    if q_client:
        filters.append("client LIKE ?")
        params.append(f"%{q_client}%")
    if only_active is not None:
        filters.append("active = ?")
        params.append(1 if only_active else 0)
    if filters:
        base_query += " WHERE " + " AND ".join(filters)
    count_q = f"SELECT COUNT(1) FROM ({base_query})"
    cur.execute(count_q, params)
    total = cur.fetchone()[0]

    base_query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    cur.execute(base_query, params)
    rows = [row_to_dict(r) for r in cur.fetchall()]
    db.close()
    return {"count": total, "page": page, "per_page": per_page, "licenses": rows}

@app.post("/admin/revoke")
def admin_revoke(payload: AdminKeyRequest = Body(...), admin: bool = Depends(require_admin)):
    key = payload.key
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE licenses SET active = 0 WHERE key = ?", (key,))
    if cur.rowcount == 0:
        db.close()
        raise HTTPException(status_code=404, detail="Key não encontrada")
    db.commit()
    db.close()
    return {"status": "ok", "message": "licença revogada"}

@app.post("/admin/reset-device")
def admin_reset_device(payload: AdminKeyRequest = Body(...), admin: bool = Depends(require_admin)):
    key = payload.key
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE licenses SET bound_device_id = NULL WHERE key = ?", (key,))
    if cur.rowcount == 0:
        db.close()
        raise HTTPException(status_code=404, detail="Key não encontrada")
    db.commit()
    db.close()
    return {"status": "ok", "message": "bound_device_id removido"}

@app.post("/admin/delete")
def admin_delete(payload: AdminKeyRequest = Body(...), admin: bool = Depends(require_admin)):
    key = payload.key
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM licenses WHERE key = ?", (key,))
    if cur.rowcount == 0:
        db.close()
        raise HTTPException(status_code=404, detail="Key não encontrada")
    db.commit()
    db.close()
    return {"status": "ok", "message": "license deleted"}

@app.post("/admin/extend")
def admin_extend(payload: ExtendRequest = Body(...), admin: bool = Depends(require_admin)):
    if payload.extra_days <= 0:
        raise HTTPException(status_code=400, detail="extra_days tem que ser positivo")
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT expiration FROM licenses WHERE key = ?", (payload.key,))
    row = cur.fetchone()
    if not row:
        db.close()
        raise HTTPException(status_code=404, detail="Key não encontrada")
    current = row["expiration"]
    if current:
        new_date = date.fromisoformat(current) + timedelta(days=payload.extra_days)
    else:
        new_date = date.today() + timedelta(days=payload.extra_days)
    cur.execute("UPDATE licenses SET expiration = ? WHERE key = ?", (new_date.isoformat(), payload.key))
    db.commit()
    db.close()
    return {"status": "ok", "new_expiration": new_date.isoformat()}

# ---------------------------
# Simple health check & info endpoints
# ---------------------------
@app.get("/admin/info")
def admin_info(admin: bool = Depends(require_admin)):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT COUNT(1) FROM licenses")
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(1) FROM licenses WHERE active = 1")
    active = cur.fetchone()[0]
    db.close()
    return {
        "total_licenses": total,
        "active_licenses": active,
        "env": {
            "db_path": DB_PATH,
            "admin_token_set": ADMIN_TOKEN != "CHANGE_THIS_TOKEN"
        }
    }

# ---------------------------
# Error handlers (friendly)
# ---------------------------
@app.exception_handler(HTTPException)
def custom_http_exception_handler(request, exc):
    # mantém default behavior, mas poderia logar em arquivo externo
    return fastapi.responses.JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

# ---------------------------
# Requirements note (for your reference)
# ---------------------------
# requirements.txt should include:
# fastapi
# uvicorn
# python-dotenv   (optional)
