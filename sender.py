import os, csv, time, base64, json, smtplib, mimetypes, re, datetime
from pathlib import Path
from email.message import EmailMessage

from dotenv import load_dotenv
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
import qrcode
from qrcode import constants

EVENT_ID = "boat-10-06-26"
EXPIRY_DATE = datetime.datetime(2026, 10, 16, 0, 0, 0, tzinfo=datetime.timezone.utc)

BASE_DIR = Path(__file__).parent.resolve()
CSV_PATH = BASE_DIR / "buyer.csv"
OUT_DIR = BASE_DIR / "tickets_out"; OUT_DIR.mkdir(exist_ok=True)
KEY_DIR = BASE_DIR / "keys"; KEY_DIR.mkdir(exist_ok=True)
LOG_DIR = BASE_DIR / "email_out"; LOG_DIR.mkdir(exist_ok=True)

SUBJECT = "Your Ticket(s) – IndianSoc Boat Party – 10th Jun 2026"
BODY_INTRO = (
    "Thanks for purchasing a ticket for Boat Party 2026.\n"
    "Attached are your QR ticket(s). Each person needs ONE QR at entry.\n\n"
    "• Location: Tower Millenium Pier.\n"
    "• Boarding starts at 6pm.\n"
    "• Boarding departs at 6:30pm.\n"
    "• Refreshments available to purchase.\n"
    "• Please ensure to bring valid government and student ID to the event.\n"
    "• Please show a clear screen or printed QR when you arrive.\n"
    "• If you purchased multiple spots, you'll find multiple QRs attached.\n"
    "• Each QR admits one person once.\n\n"
    "If images don't load, backup ticket codes are included at the end.\n\n"
    "We can't wait to welcome you!\nIndian Society Committee\n"
)
SMTP_TIMEOUT = 30

load_dotenv()
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "")
REPLY_TO = os.getenv("REPLY_TO", SMTP_FROM)

if not all([SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM]):
    print("Error: Missing SMTP config in .env (HOST, PORT, USER, PASS, FROM)")
    raise SystemExit(1)

sk_path = KEY_DIR / "ed25519.sk"
pk_path = KEY_DIR / "ed25519.pk"
if not sk_path.exists():
    _sk = SigningKey.generate()
    sk_path.write_bytes(_sk.encode(encoder=RawEncoder))
    pk_path.write_bytes(_sk.verify_key.encode(encoder=RawEncoder))
    print("[keys] Generated new Ed25519 keypair")

sk = SigningKey(sk_path.read_bytes())
pk = sk.verify_key.encode(RawEncoder)
(OUT_DIR / "public_key.bin").write_bytes(pk)

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def sign_payload(payload: dict) -> str:
    js = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = sk.sign(js).signature
    return b64u(js) + "." + b64u(sig)

def make_qr_png(data: str, out_path: Path):
    qr = qrcode.QRCode(
        version=None, error_correction=constants.ERROR_CORRECT_Q,
        box_size=10, border=2
    )
    qr.add_data(data)
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(out_path)

def normalise_row(row: dict) -> dict:
    return {k.strip().lower(): (v or "").strip() for k, v in row.items()}

issued_csv_path = OUT_DIR / "issued_tickets.csv"
already_issued: set[str] = set()

if issued_csv_path.exists():
    with issued_csv_path.open("r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            tid = (row.get("ticket_id") or "").strip()
            if tid:
                already_issued.add(tid)

print(f"[init] {len(already_issued)} tickets already issued")

write_header = not issued_csv_path.exists()
issued_file = issued_csv_path.open("a", newline="", encoding="utf-8")
issued_w = csv.writer(issued_file)
if write_header:
    issued_w.writerow(["ticket_id", "email", "exp", "token"])

elog_path = LOG_DIR / "email_log.csv"
elog_file = elog_path.open("a", newline="", encoding="utf-8")
elog_w = csv.writer(elog_file)
if not elog_path.stat().st_size:
    elog_w.writerow(["ts", "email", "num_tickets", "status", "error"])

if not CSV_PATH.exists():
    print(f"Error: {CSV_PATH} not found")
    raise SystemExit(1)

rows_to_process = []
with CSV_PATH.open("r", newline="", encoding="utf-8-sig") as f:
    reader = csv.DictReader(f)
    headers = {c.strip().lower() for c in (reader.fieldnames or [])}
    required = {"email", "quantity", "login"}
    if not required <= headers:
        raise ValueError(f"CSV missing columns: {required - headers}")

    for raw in reader:
        row = normalise_row(raw)
        email = row.get("email", "").lower()
        login = row.get("login", "")
        qty_raw = row.get("quantity", "1")
        firstname_raw = row.get("first name", row.get("firstname", ""))
        student = 1 if row.get("student", "").upper() == "Y" else 0

        if not re.match(r"^[A-Z0-9._%+\-']+@[A-Z0-9.\-]+\.[A-Z]{2,}$", email, re.I):
            print(f"[skip] Invalid email: '{email}'")
            continue
        if not login:
            print(f"[skip] No login for {email}")
            continue

        try:
            qty = max(1, int(qty_raw))
        except ValueError:
            qty = 1

        firstname = firstname_raw.capitalize() if firstname_raw else ""
        rows_to_process.append((email, qty, login, firstname, student))

print(f"[csv] {len(rows_to_process)} valid rows loaded")

exp_ts = int(EXPIRY_DATE.timestamp())
print(f"[config] Tickets expire: {EXPIRY_DATE.isoformat()} (unix {exp_ts})")

use_ssl = (SMTP_PORT == 465)
if use_ssl:
    smtp = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT)
else:
    smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT)
    smtp.starttls()
smtp.login(SMTP_USER, SMTP_PASS)

total_sent = 0
total_skipped = 0

for email, qty, login, firstname, student in rows_to_process:
    tickets_to_create = []
    for i in range(1, qty + 1):
        ticket_id = f"{login}-{i:03d}"
        if ticket_id not in already_issued:
            tickets_to_create.append((ticket_id, i))

    if not tickets_to_create:
        print(f"[skip] {email} — already fully issued")
        total_skipped += 1
        continue

    attachments = []
    backup_codes = []
    pending_rows = []

    for ticket_id, i in tickets_to_create:
        payload = {
            "event_id": EVENT_ID,
            "ticket_id": ticket_id,
            "email": email,
            "exp": exp_ts,
            "student": student,
        }
        token = sign_payload(payload)
        img_path = OUT_DIR / f"{ticket_id}.png"
        make_qr_png(token, img_path)

        pending_rows.append([ticket_id, email, exp_ts, token])
        attachments.append(img_path)
        backup_codes.append(ticket_id)

    msg = EmailMessage()
    msg["Subject"] = SUBJECT
    msg["From"] = SMTP_FROM
    msg["To"] = email
    if REPLY_TO:
        msg["Reply-To"] = REPLY_TO

    greet = f"Hi {firstname}," if firstname else "Hi,"
    body = (
        greet + "\n\n" + BODY_INTRO
        + "\nBackup ticket codes:\n"
        + "\n".join(f"  • {c}" for c in backup_codes)
        + "\n"
    )
    msg.set_content(body)

    for p in attachments:
        ctype, _ = mimetypes.guess_type(str(p))
        if not ctype:
            ctype = "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        msg.add_attachment(p.read_bytes(), maintype=maintype, subtype=subtype, filename=p.name)

    try:
        smtp.send_message(msg)
        for row in pending_rows:
            issued_w.writerow(row)
            already_issued.add(row[0])
        issued_file.flush()
        print(f"[sent] {email}: {len(attachments)} ticket(s)")
        elog_w.writerow([int(time.time()), email, len(attachments), "sent", ""])
        total_sent += 1
    except Exception as e:
        print(f"[FAIL] {email}: {e}")
        elog_w.writerow([int(time.time()), email, len(attachments), "failed", str(e)])

smtp.quit()
issued_file.close()
elog_file.close()

print(f"\n[done] Sent: {total_sent}, Skipped (already issued): {total_skipped}")
print(f"[out]  Issued CSV : {issued_csv_path}")
print(f"[out]  Public key : {OUT_DIR / 'public_key.bin'}")
print(f"[out]  Email log  : {elog_path}")
