import os, time, json, base64, sqlite3, csv
from pathlib import Path

from fastapi import FastAPI, Body, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from nacl.encoding import RawEncoder

ROOT_DIR = Path(__file__).parent.resolve()
DATA_DIR = Path(os.getenv("TICKETS_DIR", ROOT_DIR / "tickets_out"))
DB_PATH = ROOT_DIR / "checkins.db"
PUBKEY_PATH = DATA_DIR / "public_key.bin"
ISSUED_CSV = DATA_DIR / "issued_tickets.csv"

EVENT_ID = os.getenv("EVENT_ID", "boat-10-06-26")
GRACE_SECONDS = int(os.getenv("GRACE_SECONDS", "5"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

if not ADMIN_TOKEN:
    raise RuntimeError("ADMIN_TOKEN must be set")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_verify_key: VerifyKey = None

def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def ensure_schema_and_import():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tickets(
            ticket_id TEXT PRIMARY KEY,
            email     TEXT,
            exp       INTEGER,
            token     TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS checkins(
            ticket_id TEXT,
            ts        INTEGER
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_checkins_tid ON checkins(ticket_id)")
    conn.commit()

    if not ISSUED_CSV.exists():
        print("Warning: issued_tickets.csv not found — no tickets loaded")
        conn.close()
        return

    rows = []
    with ISSUED_CSV.open("r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            tid = (r.get("ticket_id") or "").strip()
            eml = (r.get("email") or "").strip().lower()
            exp = int((r.get("exp") or "0").strip() or 0)
            tok = (r.get("token") or "").strip()
            if tid and eml and tok:
                rows.append((tid, eml, exp, tok))

    if rows:
        cur.executemany(
            "INSERT OR IGNORE INTO tickets(ticket_id,email,exp,token) VALUES(?,?,?,?)",
            rows
        )
        conn.commit()
        count = cur.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
        print(f"[db] {count} tickets in DB ({len(rows)} checked from CSV)")

    conn.close()

def load_pubkey() -> VerifyKey:
    if not PUBKEY_PATH.exists():
        raise RuntimeError(f"public_key.bin not found at {PUBKEY_PATH}")
    return VerifyKey(PUBKEY_PATH.read_bytes(), encoder=RawEncoder)

def _checkin_logic(cur, ticket_id: str, now_ts: int) -> dict:
    cur.execute(
        "SELECT ts FROM checkins WHERE ticket_id = ? ORDER BY ts DESC LIMIT 1",
        (ticket_id,)
    )
    row = cur.fetchone()

    if row is None:
        cur.execute("INSERT INTO checkins(ticket_id, ts) VALUES(?,?)", (ticket_id, now_ts))
        return {"status": "ok_first_entry", "message": "Valid – First Entry"}

    last_ts = int(row[0])
    delta = now_ts - last_ts

    if delta < GRACE_SECONDS:
        cur.execute("INSERT INTO checkins(ticket_id, ts) VALUES(?,?)", (ticket_id, now_ts))
        return {"status": "ok_recent", "message": f"Valid (re-scan {delta}s ago)"}

    return {
        "status": "duplicate",
        "message": f"DUPLICATE – last scanned {delta}s ago",
        "last_checkin": last_ts,
    }

@app.on_event("startup")
def _on_startup():
    global _verify_key
    ensure_schema_and_import()
    _verify_key = load_pubkey()
    print(f"[startup] Event: {EVENT_ID}, Grace: {GRACE_SECONDS}s")

@app.get("/", response_class=HTMLResponse)
def index():
    page = ROOT_DIR / "scanner.html"
    if not page.exists():
        return HTMLResponse("<h1>scanner.html not found</h1>", status_code=404)
    return FileResponse(str(page))

@app.get("/jsQR.js")
def jsqr_file():
    p = ROOT_DIR / "jsQR.js"
    if not p.exists():
        return HTMLResponse("jsQR.js not found", status_code=404)
    return FileResponse(str(p), media_type="application/javascript")

@app.get("/health")
def health():
    conn = get_db()
    ticket_count = conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
    checkin_count = conn.execute("SELECT COUNT(DISTINCT ticket_id) FROM checkins").fetchone()[0]
    conn.close()
    return {
        "ok": True,
        "event_id": EVENT_ID,
        "grace_seconds": GRACE_SECONDS,
        "tickets_loaded": ticket_count,
        "checked_in": checkin_count,
    }

@app.post("/admin/reload")
def admin_reload(x_admin_token: str = Header(default="")):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Bad token")
    try:
        ensure_schema_and_import()
        return {"ok": True, "message": "Tickets reloaded from CSV"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.post("/verify")
def verify(token: str = Body(..., embed=True)):
    try:
        if "." not in token:
            return JSONResponse({"status": "error", "message": "Malformed token"}, status_code=400)

        js_b64, sig_b64 = token.split(".", 1)
        try:
            js = b64u_decode(js_b64)
            sig = b64u_decode(sig_b64)
            _verify_key.verify(js, sig)
        except BadSignatureError:
            return {"status": "error", "message": "Invalid signature"}
        except Exception:
            return {"status": "error", "message": "Malformed token"}

        payload = json.loads(js.decode("utf-8"))
        now = int(time.time())

        if payload.get("event_id") != EVENT_ID:
            return {"status": "error", "message": "Wrong event", "payload": payload}
        if now > int(payload.get("exp", 0)):
            return {"status": "error", "message": "Ticket expired", "payload": payload}

        ticket_id = payload.get("ticket_id")
        if not ticket_id:
            return {"status": "error", "message": "No ticket_id in payload"}

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT ticket_id FROM tickets WHERE ticket_id = ?", (ticket_id,))
        if not cur.fetchone():
            conn.close()
            return {"status": "error", "message": "Unknown ticket (not in issued list)", "payload": payload}

        result = _checkin_logic(cur, ticket_id, now)
        conn.commit()
        conn.close()
        return {**result, "payload": payload, "ticket_id": ticket_id}

    except Exception as e:
        return JSONResponse({"status": "error", "message": f"Server error: {e}"}, status_code=500)

@app.post("/manual_verify")
def manual_verify(ticket_id: str = Body(..., embed=True)):
    try:
        ticket_id = (ticket_id or "").strip()
        if not ticket_id:
            return JSONResponse({"status": "error", "message": "No ticket_id provided"}, status_code=400)

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT email, exp FROM tickets WHERE ticket_id = ?", (ticket_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return JSONResponse({"status": "error", "message": "Unknown ticket ID"}, status_code=404)

        email, exp = row
        payload = {"ticket_id": ticket_id, "email": email, "exp": exp}

        if int(time.time()) > int(exp):
            conn.close()
            return {"status": "error", "message": "Ticket expired", "payload": payload}

        result = _checkin_logic(cur, ticket_id, int(time.time()))
        conn.commit()
        conn.close()
        return {**result, "payload": payload, "ticket_id": ticket_id}

    except Exception as e:
        return JSONResponse({"status": "error", "message": f"Server error: {e}"}, status_code=500)
