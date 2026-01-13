# main.py
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import sqlite3
from datetime import date, datetime
import os
import secrets
import string

app = FastAPI()
DB_NAME = "licenses.db"
# Define um token admin simples. Configure via variável de ambiente ADMIN_TOKEN.
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "CHANGE_THIS_TOKEN")


def get_db():
    # conecta por chamada (evita problemas de thread). Row factory facilita leitura.
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


@app.on_event("startup")
def startup():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            active INTEGER,
            expiration TEXT,
            single_machine INTEGER,
            bound_device_id TEXT
        )
    """)
    db.commit()
    # garante colunas adicionais sem quebrar DB já existente
    cur.execute("PRAGMA table_info(licenses)")
    cols = [r["name"] for r in cur.fetchall()]
    if "client" not in cols:
        cur.execute("ALTER TABLE licenses ADD COLUMN client TEXT")
    if "created_at" not in cols:
        cur.execute("ALTER TABLE licenses ADD COLUMN created_at TEXT")
    db.commit()
    db.close()


def generate_key():
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    blocks = []
    for _ in range(4):
        blocks.append("".join(secrets.choice(chars) for _ in range(5)))
    return "-".join(blocks)


class CreateLicenseRequest(BaseModel):
    key: str | None = None            # se não vier, geramos
    client: str | None = None
    expiration: str | None = None     # 'YYYY-MM-DD' ou null
    single_machine: bool = True
    active: bool = True


class LicenseRequest(BaseModel):
    key: str
    device_id: str


@app.post("/create")
def create_license(req: CreateLicenseRequest, x_admin_token: str | None = Header(None)):
    # Autenticação admin simples via header X-Admin-Token
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    key = req.key.strip() if req.key else generate_key()
    expiration = req.expiration if req.expiration else None

    # valida data, se fornecida
    if expiration:
        try:
            _ = date.fromisoformat(expiration)
        except Exception:
            raise HTTPException(status_code=400, detail="expiration deve ser YYYY-MM-DD")

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
            # primeira ativação: grava bind
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


# endpoints admin úteis (list / get)
@app.get("/admin/list")
def admin_list(x_admin_token: str | None = Header(None)):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT key, active, expiration, single_machine, bound_device_id, client, created_at FROM licenses")
    rows = [dict(r) for r in cur.fetchall()]
    db.close()
    return {"count": len(rows), "licenses": rows}


@app.get("/")
def root():
    return {"status": "ok"}
