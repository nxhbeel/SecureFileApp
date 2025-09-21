import os
import sys
import json
import base64
import secrets
import re
import time
import shutil
import sqlite3
from datetime import datetime, timezone
import customtkinter as ctk
from tkinter import filedialog, messagebox
import bcrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from argon2.low_level import hash_secret_raw, Type as Argon2Type
import pyotp
import qrcode
from PIL import Image, ImageTk
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pickle

APP_NAME = "SecureFileApp"
APP_VERSION = "1.0"

if sys.platform.startswith("win"):
    default_dir = os.path.join(os.getenv("APPDATA", os.path.expanduser("~")), APP_NAME)
else:
    default_dir = os.path.join(os.path.expanduser("~/.config"), APP_NAME)

try:
    os.makedirs(default_dir, exist_ok=True)
    test_file = os.path.join(default_dir, ".writetest")
    with open(test_file, "w") as f:
        f.write("test")
    os.remove(test_file)
    APP_DIR = default_dir
except (OSError, PermissionError):
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    APP_DIR = os.path.join(BASE_DIR, APP_NAME + "_data")
    os.makedirs(APP_DIR, exist_ok=True)

DB_PATH = os.path.join(APP_DIR, "users.db")
TOKEN_PATH = os.path.join(APP_DIR, "token.pickle")
LOG_PATH = os.path.join(APP_DIR, "performance.jsonl")
FIRST_RUN_NOTE = os.path.join(APP_DIR, "FIRST_RUN.txt")

MAGIC = b"SFA1"
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024

ARGON2_TIME = 3
ARGON2_MEM = 64_000
ARGON2_PAR = 2
ARGON2_SALT_SIZE = 16


RSA_BITS = 2048


OTP_VALID_WINDOW = 1
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 300

SCOPES = ['https://www.googleapis.com/auth/drive.file']
CREDENTIALS_JSON = 'credentials.json'
UPLOAD_FOLDER_NAME = 'SecureFileApp Backups'

DLP_PATTERNS = [
    ("Passwords", re.compile(r"password\s*[:=]\s*\S+", re.I)),
    ("Emails", re.compile(r"[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+", re.I)),
    ("Credit Cards", re.compile(r"\b(?:\d[ -]*?){13,16}\b")),
]


def log_event(kind: str, **fields):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    payload = {"ts": datetime.now(timezone.utc).isoformat(), "kind": kind, **fields}
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
    except Exception:
        pass

def get_drive_service():
    """
    Build an authenticated Drive v3 service using user OAuth and the drive.file scope.
    Stores the token at TOKEN_PATH.
    """
    creds = None
    if os.path.exists(TOKEN_PATH):
        try:
            with open(TOKEN_PATH, 'rb') as token:
                creds = pickle.load(token)
        except Exception:
            creds = None
    try:
        def needs_reauth(c):
            try:
                return (not c) or (not c.valid) or (not set(SCOPES).issubset(set(c.scopes or [])))
            except Exception:
                return True

        if needs_reauth(creds):
            if creds and creds.expired and creds.refresh_token and set(SCOPES).issubset(set(getattr(creds, "scopes", []))):
                creds.refresh(Request())
            else:
                if not os.path.exists(CREDENTIALS_JSON):
                    messagebox.showerror("Cloud Backup", f"Missing {CREDENTIALS_JSON}. Place it next to the app.")
                    return None
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_JSON, SCOPES)
                creds = flow.run_local_server(port=0)
            with open(TOKEN_PATH, 'wb') as token:
                pickle.dump(creds, token)
        return build('drive', 'v3', credentials=creds)
    except Exception as e:
        messagebox.showerror("Cloud Backup", f"Google Drive auth failed: {e}")
        return None


def ensure_drive_folder(service, name: str, parent_id: str = 'root') -> str:
    """
    Ensure a folder exists in My Drive (or under parent_id) and return its ID.
    No use of appDataFolder anywhere.
    """
  
    safe_name = name.replace("'", "\\'")
    q = (
        "mimeType='application/vnd.google-apps.folder' "
        f"and name='{safe_name}' "
        f"and '{parent_id}' in parents and trashed=false"
    )
    res = service.files().list(q=q, fields="files(id,name)").execute()
    items = res.get('files', [])
    if items:
        return items[0]['id']
    meta = {
        'name': name,
        'mimeType': 'application/vnd.google-apps.folder',
        'parents': [parent_id],
    }
    folder = service.files().create(body=meta, fields='id').execute()
    return folder['id']


def upload_to_drive(file_path):
    """
    Upload a file to a normal My Drive folder ("SecureFileApp Backups").
    This does NOT use the Application Data folder, so drive.file scope is sufficient.
    """
    service = get_drive_service()
    if not service:
        return
    try:
        folder_id = ensure_drive_folder(service, UPLOAD_FOLDER_NAME, parent_id='root')
        file_metadata = {
            'name': os.path.basename(file_path),
            'parents': [folder_id],
        }
       
        media = MediaFileUpload(file_path, resumable=False)
        file = service.files().create(body=file_metadata, media_body=media, fields='id,parents').execute()
        messagebox.showinfo(
            "Cloud Backup",
            f"Uploaded to My Drive → {UPLOAD_FOLDER_NAME}\nFile ID: {file.get('id')}"
        )
    except HttpError as e:
        messagebox.showerror("Cloud Backup", f"Upload failed: {e}")
    except Exception as e:
        messagebox.showerror("Cloud Backup", f"Upload failed: {e}")


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash BLOB NOT NULL,             -- bcrypt hash
    role TEXT DEFAULT 'user',
    recovery_question TEXT,
    recovery_answer_hash BLOB,
    totp_secret BLOB,
    pubkey_pem BLOB,                         -- RSA public key (PEM)
    privkey_encrypted BLOB,                  -- encrypted private key blob (JSON bytes)
    failed_login_count INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0,
    force_password_change INTEGER DEFAULT 0,
    backup_codes_json TEXT                   -- JSON array of bcrypt hashes (unused codes)
);
"""


def db_connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH)

def argon2_kdf(password: bytes, salt: bytes, *, t=ARGON2_TIME, m=ARGON2_MEM, p=ARGON2_PAR, out_len=32) -> bytes:
    return hash_secret_raw(password, salt, t, m, p, out_len, Argon2Type.ID)


def encrypt_private_key_blob(priv_pem: bytes, password: str) -> bytes:
    salt = get_random_bytes(ARGON2_SALT_SIZE)
    key = argon2_kdf(password.encode(), salt)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(b"PRIVKEYv1")
    ct, tag = cipher.encrypt_and_digest(priv_pem)
    obj = {
        "v": 1,
        "t": ARGON2_TIME,
        "m": ARGON2_MEM,
        "p": ARGON2_PAR,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "data": base64.b64encode(ct).decode(),
    }
    return json.dumps(obj).encode()


def decrypt_private_key_blob(enc_blob: bytes, password: str) -> RSA.RsaKey:
    obj = json.loads(enc_blob.decode())
    salt = base64.b64decode(obj["salt"]) ; nonce = base64.b64decode(obj["nonce"])
    tag = base64.b64decode(obj["tag"]) ; data = base64.b64decode(obj["data"])
    key = argon2_kdf(password.encode(), salt, t=obj["t"], m=obj["m"], p=obj["p"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(b"PRIVKEYv1")
    priv_pem = cipher.decrypt_and_verify(data, tag)
    return RSA.import_key(priv_pem)

def generate_backup_codes(n=10, length=10):
    codes = []
    hashes = []
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    for _ in range(n):
        code = "".join(secrets.choice(alphabet) for _ in range(length))
        codes.append(code)
        hashes.append(base64.b64encode(bcrypt.hashpw(code.encode(), bcrypt.gensalt())).decode())
    return codes, hashes


def try_consume_backup_code(username: str, code: str) -> bool:
    with db_connect() as conn:
        c = conn.cursor()
        c.execute("SELECT id, backup_codes_json FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if not row:
            return False
        uid, codes_json = row
        try:
            hashes = json.loads(codes_json or "[]")
        except Exception:
            hashes = []
        idx_to_remove = None
        for idx, h_b64 in enumerate(hashes):
            h = base64.b64decode(h_b64)
            if bcrypt.checkpw(code.encode(), h):
                idx_to_remove = idx
                break
        if idx_to_remove is None:
            return False
        del hashes[idx_to_remove]
        c.execute("UPDATE users SET backup_codes_json=? WHERE id=?", (json.dumps(hashes), uid))
        conn.commit()
        return True

def authenticate(username: str, password: str):
    with db_connect() as conn:
        c = conn.cursor()
        c.execute("SELECT id, password_hash, role, failed_login_count, locked_until FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if not row:
            return None, "User not found"
        uid, pw_hash, role, fail_count, locked_until = row
        now = int(time.time())
        if locked_until and now < locked_until:
            return None, f"Account locked. Try again in {locked_until - now}s."
        ok = bcrypt.checkpw(password.encode(), pw_hash)
        if not ok:
            fail_count = (fail_count or 0) + 1
            if fail_count >= MAX_FAILED_LOGINS:
                c.execute("UPDATE users SET failed_login_count=0, locked_until=? WHERE id=?", (now + LOCKOUT_SECONDS, uid))
            else:
                c.execute("UPDATE users SET failed_login_count=? WHERE id=?", (fail_count, uid))
            conn.commit()
            return None, "Invalid credentials"
        c.execute("UPDATE users SET failed_login_count=0, locked_until=0 WHERE id=?", (uid,))
        conn.commit()
        return {"id": uid, "username": username, "role": role}, None


def get_user_security_materials(username: str):
    with db_connect() as conn:
        c = conn.cursor()
        c.execute("SELECT totp_secret, pubkey_pem, privkey_encrypted, force_password_change, backup_codes_json FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if not row:
            return None
        totp_secret, pub_pem, priv_enc, force_change, backup_codes_json = row
        return {
            "totp_secret": totp_secret,
            "pubkey_pem": pub_pem,
            "privkey_encrypted": priv_enc,
            "force_password_change": bool(force_change),
            "backup_codes_json": backup_codes_json or "[]",
        }


def register_user(username: str, password: str, question: str, answer: str):
    try:
        with db_connect() as conn:
            c = conn.cursor()
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            secret = pyotp.random_base32().encode()
            key = RSA.generate(RSA_BITS)
            pub_pem = key.publickey().export_key()
            priv_pem = key.export_key()
            enc_blob = encrypt_private_key_blob(priv_pem, password)
            codes, codes_h = generate_backup_codes()
            c.execute(
                """
                INSERT INTO users (username, password_hash, role, recovery_question, recovery_answer_hash, totp_secret,
                                   pubkey_pem, privkey_encrypted, backup_codes_json)
                VALUES (?, ?, 'user', ?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    sqlite3.Binary(pw_hash),
                    question,
                    sqlite3.Binary(bcrypt.hashpw(answer.encode(), bcrypt.gensalt())),
                    sqlite3.Binary(secret),
                    sqlite3.Binary(pub_pem),
                    sqlite3.Binary(enc_blob),
                    json.dumps(codes_h),
                ),
            )
            conn.commit()
            return secret.decode(), codes
    except sqlite3.IntegrityError:
        return None, None


def verify_recovery(username: str, answer: str) -> bool:
    with db_connect() as conn:
        c = conn.cursor()
        c.execute("SELECT recovery_answer_hash FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if not row:
            return False
        return bcrypt.checkpw(answer.encode(), row[0])


def reset_password(username: str, new_password: str):
    with db_connect() as conn:
        c = conn.cursor()
        c.execute("SELECT privkey_encrypted FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if not row:
            return False
        new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        c.execute("UPDATE users SET password_hash=?, force_password_change=0 WHERE username=?",
                  (sqlite3.Binary(new_hash), username))
        conn.commit()
        return True

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def scan_plaintext_for_dlp(data: bytes) -> list:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []
    hits = []
    for label, rx in DLP_PATTERNS:
        if rx.search(text):
            hits.append(label)
    return hits


def write_encrypted_file(src_path: str, allowed_users: list, current_username: str) -> str:
    start = time.time()
    with open(src_path, "rb") as f:
        head = f.read(256 * 1024)
    hits = scan_plaintext_for_dlp(head)
    if hits:
        if not messagebox.askyesno("Keyword/DLP Alert", f"Potential sensitive patterns found: {', '.join(hits)}\nContinue encryption?"):
            return ""

    dek = get_random_bytes(32)
    nonce = get_random_bytes(12)

    created = int(time.time())
    header = {
        "version": 1,
        "app": APP_NAME,
        "app_version": APP_VERSION,
        "created": created,
        "filename": os.path.basename(src_path),
        "cipher": {"alg": "AES-256-GCM", "nonce": b64(nonce)},
        "acl": {"allowed_users": sorted(set(allowed_users + [current_username]))},
        "dek_wrapped": {},
    }

    missing = []
    with db_connect() as conn:
        c = conn.cursor()
        for user in header["acl"]["allowed_users"]:
            c.execute("SELECT pubkey_pem FROM users WHERE username=?", (user,))
            row = c.fetchone()
            if not row or not row[0]:
                missing.append(user)
            else:
                pubkey = RSA.import_key(row[0])
                oaep = PKCS1_OAEP.new(pubkey, hashAlgo=SHA256)
                wrapped = oaep.encrypt(dek)
                header["dek_wrapped"][user] = b64(wrapped)
    if missing:
        messagebox.showerror("Encrypt", f"Missing public keys for: {', '.join(missing)}")
        return ""

    out_path = src_path + ".sfa"
    aad = None

    with open(out_path, "wb") as out_f:
        header_json = json.dumps(header, separators=(",", ":")).encode()
        out_f.write(MAGIC)
        out_f.write(len(header_json).to_bytes(4, "big"))
        out_f.write(header_json)
        aad = MAGIC + len(header_json).to_bytes(4, "big") + header_json
        cipher = AES.new(dek, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        with open(src_path, "rb") as in_f:
            while True:
                chunk = in_f.read(CHUNK_SIZE)
                if not chunk:
                    break
                out_f.write(cipher.encrypt(chunk))
        tag = cipher.digest()
        out_f.write(tag)

    dur = time.time() - start
    log_event("encrypt", file=src_path, out=out_path, ms=int(dur * 1000), size=os.path.getsize(src_path))
    return out_path


def read_and_decrypt_file(enc_path: str, username: str, password: str) -> tuple:
    start = time.time()
    with open(enc_path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise Exception("Unsupported file format (bad magic)")
        hlen = int.from_bytes(f.read(4), "big")
        header_json = f.read(hlen)
        header = json.loads(header_json.decode())
        aad = magic + hlen.to_bytes(4, "big") + header_json
        nonce = b64d(header["cipher"]["nonce"])
        allowed = header["acl"]["allowed_users"]
        if username not in allowed:
            raise Exception("You are not authorized to decrypt this file.")
        wrapped_b64 = header["dek_wrapped"].get(username)
        if not wrapped_b64:
            raise Exception("Missing key material for user.")
        wrapped = b64d(wrapped_b64)
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT privkey_encrypted FROM users WHERE username=?", (username,))
            row = c.fetchone()
            if not row:
                raise Exception("User private key not found.")
            priv = decrypt_private_key_blob(row[0], password)
        oaep = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
        dek = oaep.decrypt(wrapped)
        tmp_out = enc_path + ".dec.tmp"
        out_real = enc_path.rsplit(".sfa", 1)[0] + ".dec"
        file_size = os.path.getsize(enc_path)
        ct_len = file_size - 8 - hlen - TAG_SIZE
        if ct_len < 0:
            raise Exception("Corrupt file")
        cipher = AES.new(dek, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        with open(tmp_out, "wb") as out_f:
            remaining = ct_len
            while remaining > 0:
                to_read = min(CHUNK_SIZE, remaining)
                chunk = f.read(to_read)
                if not chunk:
                    raise Exception("Unexpected EOF")
                out_f.write(cipher.decrypt(chunk))
                remaining -= len(chunk)
            tag = f.read(TAG_SIZE)
            try:
                cipher.verify(tag)
            except ValueError:
                out_f.flush(); out_f.close()
                try: os.remove(tmp_out)
                except Exception: pass
                raise Exception("Authentication failed: wrong key or tampered file.")
        if os.path.exists(out_real):
            try: os.remove(out_real)
            except Exception: pass
        shutil.move(tmp_out, out_real)

    dur = time.time() - start
    size = os.path.getsize(out_real) if os.path.exists(out_real) else 0
    log_event("decrypt", file=enc_path, out=out_real, ms=int(dur * 1000), size=size)

    preview = None
    try:
        with open(out_real, "rb") as f2:
            sample = f2.read(512 * 1024)
        preview = sample.decode("utf-8")
    except Exception:
        preview = None
    return out_real, preview

def ensure_tables_and_seed_admin():
    with db_connect() as conn:
        c = conn.cursor()
        c.executescript(SCHEMA)
        c.execute("SELECT COUNT(*) FROM users WHERE username=?", ("nabeel",))
        exists = c.fetchone()[0] > 0
        if not exists:
            admin_user = "nabeel"
            admin_pass = "Nabeel123"  
            pw_hash = bcrypt.hashpw(admin_pass.encode(), bcrypt.gensalt())
            secret = pyotp.random_base32().encode()
            key = RSA.generate(RSA_BITS)
            pub_pem = key.publickey().export_key()
            priv_pem = key.export_key()
            enc_blob = encrypt_private_key_blob(priv_pem, admin_pass)
            codes, codes_h = generate_backup_codes()
            c.execute(
                """
                INSERT INTO users (username, password_hash, role, recovery_question, recovery_answer_hash,
                                   totp_secret, pubkey_pem, privkey_encrypted, backup_codes_json, force_password_change)
                VALUES (?, ?, 'admin', ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    admin_user,
                    sqlite3.Binary(pw_hash),
                    "What is your favorite color?",
                    sqlite3.Binary(bcrypt.hashpw(b"blue", bcrypt.gensalt())),
                    sqlite3.Binary(secret),
                    sqlite3.Binary(pub_pem),
                    sqlite3.Binary(enc_blob),
                    json.dumps(codes_h),
                ),
            )
            conn.commit()
    
            uri = pyotp.TOTP(secret.decode()).provisioning_uri(name=admin_user, issuer_name=APP_NAME)
            note = [
                "[FIRST RUN] Admin seeded.",
                f"Username: {admin_user}",
                f"Password: {admin_pass}",
                f"TOTP secret: {secret.decode()}",
                f"Provisioning URI (scan via QR if you generate one): {uri}",
                "One‑time backup codes (use any one on OTP step):",
                *codes,
            ]
            try:
                with open(FIRST_RUN_NOTE, "w", encoding="utf-8") as f:
                    f.write("\n".join(note))
            except Exception:
                pass
            print("\n".join(note))

class OTPDialog(ctk.CTkToplevel):
    def __init__(self, parent, on_submit):
        super().__init__(parent)
        self.title("Two-Factor Authentication")
        self.geometry("320x170")
        ctk.CTkLabel(self, text="Enter 6‑digit OTP or a backup code:").pack(pady=10)
        self.entry = ctk.CTkEntry(self)
        self.entry.pack(pady=5)
        ctk.CTkButton(self, text="Verify", command=lambda: self._submit(on_submit)).pack(pady=10)
        self.bind('<Return>', lambda e: self._submit(on_submit))

    def _submit(self, cb):
        val = self.entry.get().strip()
        try: self.destroy()
        except Exception: pass
        if cb:
            self.after(0, lambda: cb(val))


class RegisterWindow(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Register")
        self.geometry("460x660")
        ctk.CTkLabel(self, text="Create Account", font=("Arial", 20)).pack(pady=10)
        self.entry_username = ctk.CTkEntry(self, placeholder_text="Username")
        self.entry_username.pack(pady=5)
        self.entry_password = ctk.CTkEntry(self, placeholder_text="Password", show="*")
        self.entry_password.pack(pady=5)
        self.entry_confirm = ctk.CTkEntry(self, placeholder_text="Confirm Password", show="*")
        self.entry_confirm.pack(pady=5)
        self.entry_question = ctk.CTkEntry(self, placeholder_text="Recovery Question")
        self.entry_question.pack(pady=5)
        self.entry_answer = ctk.CTkEntry(self, placeholder_text="Recovery Answer")
        self.entry_answer.pack(pady=5)
        self.qr_label = ctk.CTkLabel(self, text="QR will appear after account creation")
        self.qr_label.pack(pady=12)
        self.codes_box = ctk.CTkTextbox(self, height=130)
        self.codes_box.pack(pady=6, padx=10, fill="x")
        self.codes_box.insert("end", "Backup codes will appear here (save them now).\n")
        self.codes_box.configure(state="disabled")
        ctk.CTkButton(self, text="Create Account", command=self.handle_register).pack(pady=10)

    def handle_register(self):
        u = self.entry_username.get().strip()
        p = self.entry_password.get()
        c2 = self.entry_confirm.get()
        q = self.entry_question.get().strip()
        a = self.entry_answer.get().strip()
        if p != c2:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        if len(p) < 10:
            messagebox.showwarning("Weak Password", "Use at least 10 characters.")
            return
        secret, backup_codes = register_user(u, p, q, a)
        if not secret:
            messagebox.showerror("Error", "Username already exists.")
            return
        uri = pyotp.TOTP(secret).provisioning_uri(name=u, issuer_name=APP_NAME)
        qr_img = qrcode.make(uri).resize((220, 220))
        self.qr_img = ImageTk.PhotoImage(qr_img)
        self.qr_label.configure(image=self.qr_img, text="")
        self.codes_box.configure(state="normal")
        self.codes_box.delete("1.0", "end")
        self.codes_box.insert("end", "Save these one‑time backup codes in a safe place:\n\n")
        for code in backup_codes:
            self.codes_box.insert("end", code + "\n")
        self.codes_box.configure(state="disabled")
        messagebox.showinfo("2FA Setup", "Scan the QR in your Authenticator. Backup codes shown once.")


class RecoveryWindow(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Password Recovery")
        self.geometry("400x360")
        self.entry_username = ctk.CTkEntry(self, placeholder_text="Username")
        self.entry_username.pack(pady=10)
        self.entry_answer = ctk.CTkEntry(self, placeholder_text="Recovery Answer")
        self.entry_answer.pack(pady=10)
        self.entry_new_pass = ctk.CTkEntry(self, placeholder_text="New Password", show="*")
        self.entry_new_pass.pack(pady=10)
        ctk.CTkButton(self, text="Reset Password", command=self.handle_reset).pack(pady=10)

    def handle_reset(self):
        u = self.entry_username.get().strip()
        a = self.entry_answer.get().strip()
        new_p = self.entry_new_pass.get()
        if len(new_p) < 10:
            messagebox.showwarning("Weak Password", "Use at least 10 characters.")
            return
        if verify_recovery(u, a):
            if reset_password(u, new_p):
                messagebox.showinfo("Success", "Password reset. Please login.")
                try: self.destroy()
                except Exception: pass
            else:
                messagebox.showerror("Error", "Reset failed.")
        else:
            messagebox.showerror("Error", "Recovery failed. Incorrect answer.")


class Dashboard(ctk.CTk):
    def __init__(self, username, role):
        super().__init__()
        self.username = username
        self.role = role
        self.title(f"{APP_NAME} — Dashboard")
        self.geometry("700x580")
        self.build_main()

    def clear_widgets(self):
        for w in self.winfo_children():
            w.destroy()

    def build_main(self):
        self.clear_widgets()
        ctk.CTkLabel(self, text=f"Welcome, {self.username}!", font=("Arial", 22)).pack(pady=16)
        if self.role == "admin":
            ctk.CTkButton(self, text="View Users", command=self.view_users).pack(pady=6)
        ctk.CTkButton(self, text="Encrypt File", command=self.encrypt_action).pack(pady=6)
        ctk.CTkButton(self, text="Decrypt File & Preview", command=self.decrypt_action).pack(pady=6)

        self.text_preview = ctk.CTkTextbox(self, height=180)
        self.text_preview.configure(state="disabled")
        self.text_preview.pack(pady=10, padx=20, fill="both", expand=False)
        self.meta_label = ctk.CTkLabel(self, text="")
        self.meta_label.pack(pady=4)

        if self.role == "admin":
            ctk.CTkButton(self, text="Admin Tools", command=self.switch_to_admin).pack(pady=6)
        ctk.CTkButton(self, text="Logout", command=self.logout).pack(pady=14)

    def view_users(self):
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT username, role FROM users")
            users = c.fetchall()
        messagebox.showinfo("Registered Users", "\n".join([f"{u} ({r})" for u, r in users]))

    def encrypt_action(self):
        file_path = filedialog.askopenfilename(title="Select File to Encrypt",
                                               filetypes=[("All Files", "*.*")])
        if not file_path:
            return
        self.show_user_selection(file_path)

    def show_user_selection(self, file_path):
        win = ctk.CTkToplevel(self)
        win.title("Select Users Allowed to Decrypt")
        win.geometry("360x440")
        frame = ctk.CTkFrame(win)
        frame.pack(pady=10, padx=10, fill="both", expand=True)
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT username FROM users WHERE username != ?", (self.username,))
            users = [r[0] for r in c.fetchall()]
        self.user_vars = {}
        for u in users:
            var = ctk.BooleanVar()
            ctk.CTkCheckBox(frame, text=u, variable=var).pack(anchor='w', padx=6, pady=2)
            self.user_vars[u] = var
        ctk.CTkButton(win, text="Encrypt", command=lambda: self._do_encrypt(file_path, win)).pack(pady=8)

    def _do_encrypt(self, file_path, win):
        allowed = [u for u, v in self.user_vars.items() if v.get()]
        if self.username not in allowed:
            allowed.append(self.username)
        if self.role != "admin":
            with db_connect() as conn:
                c = conn.cursor()
                c.execute("SELECT username FROM users WHERE role='admin' LIMIT 1")
                row = c.fetchone()
                if row and row[0] not in allowed:
                    allowed.append(row[0])
        try: win.destroy()
        except Exception: pass
        out = write_encrypted_file(file_path, allowed, self.username)
        if out:
            messagebox.showinfo("Encryption", f"Encrypted: {out}")

    def decrypt_action(self):
        enc_path = filedialog.askopenfilename(title="Select Encrypted File",
                                              filetypes=[("SecureFileApp", "*.sfa")])
        if not enc_path:
            return
        self._prompt_password(lambda pw: self._handle_decrypt(enc_path, pw))

    def _prompt_password(self, callback):
        win = ctk.CTkToplevel(self)
        win.title("Enter Account Password")
        win.geometry("320x160")
        ctk.CTkLabel(win, text="Enter your ACCOUNT password to unlock your private key:").pack(pady=10)
        e = ctk.CTkEntry(win, show="*")
        e.pack(pady=6)
        
        def submit():
            
            val = e.get()
            try:
                win.destroy()
            except Exception:
                pass
            
            self.after(0, lambda: callback(val))
        
        ctk.CTkButton(win, text="Continue", command=submit).pack(pady=8)
        e.bind('<Return>', lambda ev: submit())

    def _handle_decrypt(self, enc_path, password):
        try:
            out_file, preview = read_and_decrypt_file(enc_path, self.username, password)
            self.text_preview.configure(state="normal")
            self.text_preview.delete("1.0", "end")
            self.text_preview.insert("end", preview if preview is not None else "[Binary or non-text content]")
            self.text_preview.configure(state="disabled")
            self.meta_label.configure(text=f"Decrypted: {os.path.basename(out_file)}")
            messagebox.showinfo("Decryption", f"Decrypted to: {out_file}")
        except Exception as e:
            messagebox.showerror("Decryption Failed", str(e))

    def switch_to_admin(self):
        self.clear_widgets()
        ctk.CTkLabel(self, text="Admin Tools", font=("Arial", 20)).pack(pady=10)
        self.log_text = ctk.CTkTextbox(self, height=220)
        self.log_text.configure(state="disabled")
        self.log_text.pack(pady=10, padx=20, fill="both")
        ctk.CTkButton(self, text="View Logs", command=self.view_logs).pack(pady=4)
        ctk.CTkButton(self, text="Clear Logs", command=self.clear_logs).pack(pady=4)
        ctk.CTkButton(self, text="Export Logs", command=self.export_logs).pack(pady=4)
        ctk.CTkButton(self, text="Upload File to Cloud", command=self.upload_cloud_action).pack(pady=6)
        ctk.CTkButton(self, text="Back", command=self.build_main).pack(pady=10)
        ctk.CTkButton(self, text="Logout", command=self.logout).pack(pady=6)

    def view_logs(self):
        try:
            with open(LOG_PATH, "r", encoding="utf-8") as f:
                logs = f.read()
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.insert("end", logs)
            self.log_text.configure(state="disabled")
        except FileNotFoundError:
            messagebox.showwarning("No Logs", "No logs found.")

    def clear_logs(self):
        try:
            open(LOG_PATH, "w").close()
            messagebox.showinfo("Logs", "Cleared.")
            self.text_preview.configure(state="normal")
            self.text_preview.delete("1.0", "end")
            self.text_preview.configure(state="disabled")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear logs: {e}")

    def export_logs(self):
        try:
            if not os.path.exists(LOG_PATH):
                messagebox.showerror("Error", "No logs to export.")
                return
            out = os.path.join(os.getcwd(), "exported_logs.jsonl")
            shutil.copyfile(LOG_PATH, out)
            messagebox.showinfo("Export", f"Logs exported to {out}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

    def upload_cloud_action(self):
        file_path = filedialog.askopenfilename(title="Select File to Upload",
                                               filetypes=[("All Supported", "*.sfa *.txt *.pdf *.json *.jsonl"),
                                                          ("Encrypted Files", "*.sfa"),
                                                          ("Text Files", "*.txt"),
                                                          ("PDF Files", "*.pdf"),
                                                          ("JSON Logs", "*.json *.jsonl")])
        if file_path:
            upload_to_drive(file_path)

    def logout(self):
        try: self.destroy()
        except Exception: pass
        app = LoginApp()
        app.mainloop()


class LoginApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} — Login")
        self.geometry("460x540")
        ctk.CTkLabel(self, text="Login", font=("Arial", 24)).pack(pady=20)
        self.entry_username = ctk.CTkEntry(self, placeholder_text="Username")
        self.entry_username.pack(pady=10)
        self.entry_password = ctk.CTkEntry(self, placeholder_text="Password", show="*")
        self.entry_password.pack(pady=10)
        ctk.CTkButton(self, text="Login", command=self.handle_login).pack(pady=10)
        ctk.CTkButton(self, text="Register", command=self.open_register_window).pack(pady=5)
        ctk.CTkButton(self, text="Forgot Password?", command=self.open_recovery_window).pack(pady=5)
        ctk.CTkButton(self, text="Show My 2FA QR (re‑auth)", command=self.show_my_2fa_qr).pack(pady=10)

    def handle_login(self):
        username = self.entry_username.get().strip()
        password = self.entry_password.get()
        user, err = authenticate(username, password)
        if not user:
            messagebox.showerror("Login Failed", err)
            return
        with db_connect() as conn:
            c = conn.cursor()
            c.execute("SELECT totp_secret FROM users WHERE username=?", (username,))
            row = c.fetchone()
        if not row or not row[0]:
            messagebox.showerror("2FA Error", "TOTP is not configured for this user. Please re-register.")
            return
        secret = row[0].decode() if isinstance(row[0], (bytes, bytearray)) else row[0]
        OTPDialog(self, lambda code: self.verify_otp_and_login(code, secret, user, password))

    def verify_otp_and_login(self, code, secret, user, password):
        totp = pyotp.TOTP(secret)
        ok = False
        if code and code.isdigit() and len(code) in (6, 7):
            ok = totp.verify(code, valid_window=OTP_VALID_WINDOW)
        if not ok:
            if try_consume_backup_code(user["username"], code):
                ok = True
        if ok:
            try: self.destroy()
            except Exception: pass
            dash = Dashboard(user["username"], user["role"])
            dash.mainloop()
        else:
            messagebox.showerror("Invalid OTP", "The OTP/backup code is incorrect or expired.")

    def show_my_2fa_qr(self):
        username = self.entry_username.get().strip()
        password = self.entry_password.get()
        if not username or not password:
            messagebox.showwarning("Missing", "Enter username and password first.")
            return
        user, err = authenticate(username, password)
        if not user:
            messagebox.showerror("Auth Failed", err)
            return
        mats = get_user_security_materials(username)
        if not mats or not mats.get("totp_secret"):
            messagebox.showerror("No 2FA", "No TOTP secret for this user.")
            return
        def after_otp(code):
            secret = mats["totp_secret"].decode() if isinstance(mats["totp_secret"], (bytes, bytearray)) else mats["totp_secret"]
            totp = pyotp.TOTP(secret)
            if not totp.verify(code, valid_window=OTP_VALID_WINDOW):
                messagebox.showerror("Invalid OTP", "OTP did not verify.")
                return
            uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=APP_NAME)
            img = qrcode.make(uri).resize((240, 240))
            win = ctk.CTkToplevel(self)
            win.title(f"2FA QR for {username}")
            win.geometry("300x360")
            win._qr_img = ImageTk.PhotoImage(img)
            ctk.CTkLabel(win, text=f"Scan in Authenticator for\n{username}", font=("Arial", 14)).pack(pady=6)
            ctk.CTkLabel(win, image=win._qr_img, text="").pack(pady=6)
        OTPDialog(self, after_otp)

    def open_register_window(self):
        RegisterWindow(self)

    def open_recovery_window(self):
        RecoveryWindow(self)
if __name__ == "__main__":
    with db_connect() as conn:
        conn.executescript(SCHEMA)
    ensure_tables_and_seed_admin()
    app = LoginApp()
    app.mainloop()
