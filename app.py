import os
import hashlib
import secrets
import sqlite3
import mimetypes
import base64
import tempfile
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, g, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from crypto_utils import (
    encrypt_file, decrypt_file,
    generate_rsa_keypair, rsa_encrypt_key, rsa_decrypt_key,
    sign_data, verify_signature,
    compute_hmac, verify_hmac,
    generate_totp_secret, get_totp_uri, verify_totp,
    check_password_strength,
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DATABASE = os.path.join(os.path.dirname(__file__), "database.db")

# HMAC secret for tamper-proof logs
HMAC_SECRET = os.environ.get("HMAC_SECRET", secrets.token_hex(32))

# Email config (optional)
SMTP_SERVER = os.environ.get("SMTP_SERVER", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
EMAIL_ENABLED = bool(SMTP_SERVER and SMTP_USER and SMTP_PASS)

ADMIN_USERNAME = "admin"
ADMIN_DEFAULT_PASSWORD = "Admin@123"

# Track active sessions - one login per user
active_sessions = {}


# ── Database ──────────────────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT DEFAULT '',
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            rsa_public_key TEXT DEFAULT '',
            rsa_private_key TEXT DEFAULT '',
            totp_secret TEXT DEFAULT '',
            totp_enabled INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            mime_type TEXT DEFAULT '',
            owner_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            encrypted_aes_key TEXT NOT NULL,
            file_password_hash TEXT DEFAULT '',
            digital_signature TEXT DEFAULT '',
            expiry_time TIMESTAMP NOT NULL,
            max_views INTEGER DEFAULT 0,
            current_views INTEGER DEFAULT 0,
            allow_download INTEGER DEFAULT 1,
            max_downloads INTEGER DEFAULT 0,
            current_downloads INTEGER DEFAULT 0,
            self_destruct INTEGER DEFAULT 0,
            is_revoked INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            ip_address TEXT DEFAULT '',
            hmac_hash TEXT DEFAULT '',
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    # Create admin user if not exists
    admin = db.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
    if not admin:
        priv, pub = generate_rsa_keypair()
        db.execute(
            "INSERT INTO users (username, password_hash, is_admin, rsa_public_key, rsa_private_key) VALUES (?, ?, 1, ?, ?)",
            (ADMIN_USERNAME, generate_password_hash(ADMIN_DEFAULT_PASSWORD), pub, priv),
        )
    db.commit()


with app.app_context():
    init_db()


# ── Helpers ───────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        # Check if this is still the active session
        uid = session["user_id"]
        token = session.get("session_token", "")
        if uid in active_sessions and active_sessions[uid] != token:
            session.clear()
            flash("You have been logged out because your account was logged in from another location.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper


def log_access(db, file_id, user_id, action, status):
    """Log access with HMAC-SHA256 for tamper detection."""
    ip = request.remote_addr or ""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    # Create HMAC of log entry to detect tampering
    log_message = f"{file_id}|{user_id}|{action}|{status}|{ip}|{timestamp}"
    hmac_hash = compute_hmac(log_message, HMAC_SECRET)
    db.execute(
        """INSERT INTO access_logs (file_id, user_id, action, status, ip_address, hmac_hash, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (file_id, user_id, action, status, ip, hmac_hash, timestamp),
    )
    db.commit()


def send_notification_email(to_email, subject, body):
    if not EMAIL_ENABLED or not to_email:
        return False
    try:
        msg = MIMEText(body, "html")
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = to_email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        return True
    except Exception:
        return False


def format_size(size_bytes):
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def decrypt_file_data(f, receiver_private_key):
    """Decrypt a file: unwrap AES key with RSA, then decrypt file."""
    filepath = os.path.join(UPLOAD_FOLDER, f["stored_name"])
    with open(filepath, "rb") as ef:
        raw = ef.read()
    iv = raw[:16]
    ciphertext = raw[16:]
    # RSA-unwrap the AES key
    encrypted_aes_key = base64.b64decode(f["encrypted_aes_key"])
    aes_key = rsa_decrypt_key(encrypted_aes_key, receiver_private_key)
    return decrypt_file(ciphertext, aes_key, iv)


def is_previewable(mime_type):
    if not mime_type:
        return False
    return (
        mime_type.startswith("image/")
        or mime_type.startswith("text/")
        or mime_type == "application/pdf"
    )


@app.template_filter("filesize")
def filesize_filter(value):
    return format_size(value)


# ── Routes: Auth ──────────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        email = request.form.get("email", "").strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))

        # Check password strength
        strength = check_password_strength(password)
        if strength["score"] < 2:
            flash(f"Password too weak ({strength['label']}). {'; '.join(strength['feedback'])}", "danger")
            return redirect(url_for("register"))

        db = get_db()
        if db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            flash("Username already taken.", "danger")
            return redirect(url_for("register"))

        # Generate RSA-2048 key pair for this user
        private_key, public_key = generate_rsa_keypair()

        db.execute(
            """INSERT INTO users (username, email, password_hash, rsa_public_key, rsa_private_key)
               VALUES (?, ?, ?, ?, ?)""",
            (username, email, generate_password_hash(password), public_key, private_key),
        )
        db.commit()
        rsa_obj = __import__("Crypto.PublicKey", fromlist=["RSA"]).RSA.import_key(public_key)
        flash(f"Registration successful! RSA-{rsa_obj.size_in_bits()} key pair generated. Modulus (hex): {format(rsa_obj.n, 'x')[:40]}... | Exponent: {rsa_obj.e}", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/check_password_strength", methods=["POST"])
def check_pw_strength():
    """AJAX endpoint for real-time password strength checking."""
    password = request.json.get("password", "")
    result = check_password_strength(password)
    return jsonify(result)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        totp_code = request.form.get("totp_code", "").strip()

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            # Check 2FA if enabled
            if user["totp_enabled"] and user["totp_secret"]:
                if not totp_code:
                    flash("2FA code required.", "warning")
                    return render_template("login.html", needs_2fa=True, username=username)
                if not verify_totp(user["totp_secret"], totp_code):
                    flash("Invalid 2FA code.", "danger")
                    return render_template("login.html", needs_2fa=True, username=username)

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            # Enforce single session per user
            session["session_token"] = __import__("secrets").token_hex(16)
            active_sessions[user["id"]] = session["session_token"]
            flash(f"Welcome, {username}!", "success")
            if user["is_admin"]:
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html", needs_2fa=False)


@app.route("/logout")
def logout():
    uid = session.get("user_id")
    if uid and uid in active_sessions:
        del active_sessions[uid]
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# ── Routes: 2FA Setup ────────────────────────────────────────────

@app.route("/setup_2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "enable":
            totp_code = request.form.get("totp_code", "").strip()
            totp_secret = request.form.get("totp_secret", "")
            if verify_totp(totp_secret, totp_code):
                db.execute(
                    "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
                    (totp_secret, session["user_id"]),
                )
                db.commit()
                flash("Two-factor authentication enabled!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid code. Please try again.", "danger")
                return redirect(url_for("setup_2fa"))

        elif action == "disable":
            db.execute(
                "UPDATE users SET totp_enabled = 0, totp_secret = '' WHERE id = ?",
                (session["user_id"],),
            )
            db.commit()
            flash("Two-factor authentication disabled.", "info")
            return redirect(url_for("dashboard"))

    # Generate new TOTP secret for setup
    totp_secret = generate_totp_secret()
    totp_uri = get_totp_uri(totp_secret, user["username"])

    return render_template(
        "setup_2fa.html",
        user=user,
        totp_secret=totp_secret,
        totp_uri=totp_uri,
    )


# ── Routes: Dashboard ────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = session["user_id"]

    shared = db.execute("""
        SELECT f.*, u.username AS receiver_name
        FROM files f JOIN users u ON f.receiver_id = u.id
        WHERE f.owner_id = ?
        ORDER BY f.created_at DESC
    """, (uid,)).fetchall()

    received = db.execute("""
        SELECT f.*, u.username AS owner_name
        FROM files f JOIN users u ON f.owner_id = u.id
        WHERE f.receiver_id = ?
        ORDER BY f.created_at DESC
    """, (uid,)).fetchall()

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    total_shared = len(shared)
    total_received = len(received)
    active_shared = sum(1 for f in shared if f["expiry_time"] > now)

    # Check if user has 2FA enabled
    user = db.execute("SELECT totp_enabled FROM users WHERE id = ?", (uid,)).fetchone()

    return render_template(
        "dashboard.html",
        shared=shared, received=received, now=now,
        total_shared=total_shared, total_received=total_received,
        active_shared=active_shared, totp_enabled=user["totp_enabled"],
    )


# ── Routes: Upload & Share ───────────────────────────────────────

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    db = get_db()
    users = db.execute(
        "SELECT id, username FROM users WHERE id != ? AND is_admin = 0",
        (session["user_id"],),
    ).fetchall()

    if request.method == "POST":
        file = request.files.get("file")
        receiver_id = request.form.get("receiver_id", type=int)
        expiry_hours = request.form.get("expiry_hours", type=int, default=24)
        file_password = request.form.get("file_password", "").strip()
        max_views = request.form.get("max_views", type=int, default=0)
        allow_download = 1 if request.form.get("allow_download") else 0
        max_downloads = request.form.get("max_downloads", type=int, default=0)
        self_destruct = 1 if request.form.get("self_destruct") else 0

        if not file or not receiver_id:
            flash("File and receiver are required.", "danger")
            return redirect(url_for("upload"))

        file_bytes = file.read()
        file_size = len(file_bytes)
        original_name = secure_filename(file.filename)
        mime_type = mimetypes.guess_type(original_name)[0] or "application/octet-stream"

        # SHA-256 hash for integrity
        file_hash = hashlib.sha256(file_bytes).hexdigest()

        # Generate random AES-256 key and encrypt file
        aes_key = secrets.token_bytes(32)
        encrypted_data, iv = encrypt_file(file_bytes, aes_key)

        # Store encrypted file (IV prepended)
        stored_name = secrets.token_hex(16) + ".enc"
        filepath = os.path.join(UPLOAD_FOLDER, stored_name)
        with open(filepath, "wb") as f:
            f.write(iv + encrypted_data)

        # RSA key wrapping: encrypt AES key with RECEIVER's public key
        receiver = db.execute("SELECT rsa_public_key, username, email FROM users WHERE id = ?", (receiver_id,)).fetchone()
        encrypted_aes_key = rsa_encrypt_key(aes_key, receiver["rsa_public_key"])
        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode("utf-8")

        # Digital signature: owner signs the file hash with their private key
        owner = db.execute("SELECT rsa_private_key FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        digital_signature = sign_data(file_hash, owner["rsa_private_key"])

        expiry_time = datetime.utcnow() + timedelta(hours=expiry_hours)
        file_pw_hash = generate_password_hash(file_password) if file_password else ""

        db.execute(
            """INSERT INTO files
               (original_name, stored_name, file_hash, file_size, mime_type,
                owner_id, receiver_id, encrypted_aes_key, file_password_hash,
                digital_signature, expiry_time,
                max_views, allow_download, max_downloads, self_destruct)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                original_name, stored_name, file_hash, file_size, mime_type,
                session["user_id"], receiver_id,
                encrypted_aes_key_b64, file_pw_hash,
                digital_signature,
                expiry_time.strftime("%Y-%m-%d %H:%M:%S"),
                max_views, allow_download, max_downloads, self_destruct,
            ),
        )
        db.commit()

        # Email notification
        if receiver["email"]:
            send_notification_email(
                receiver["email"],
                "New file shared with you - Secure File Share",
                f"""<h3>New File Shared!</h3>
                <p><b>{session['username']}</b> shared an encrypted file with you:</p>
                <ul>
                    <li><b>File:</b> {original_name}</li>
                    <li><b>Size:</b> {format_size(file_size)}</li>
                    <li><b>Encryption:</b> AES-256-CBC + RSA-2048 key wrapping</li>
                    <li><b>Signed:</b> RSA-PSS digital signature</li>
                    <li><b>Expires:</b> {expiry_time.strftime('%Y-%m-%d %H:%M UTC')}</li>
                    <li><b>Password protected:</b> {'Yes' if file_password else 'No'}</li>
                </ul>
                <p>Log in to download it before it expires.</p>""",
            )

        pw_note = " (password protected)" if file_password else ""
        flash(
            f"File encrypted (AES-256), key wrapped (RSA-2048), signed (RSA-PSS), "
            f"and shared! Expires in {expiry_hours}h.{pw_note}",
            "success",
        )
        return redirect(url_for("dashboard"))

    return render_template("upload.html", users=users)


# ── Routes: File Password Verification ───────────────────────────

@app.route("/verify_password/<int:file_id>", methods=["GET", "POST"])
@login_required
def verify_password(file_id):
    db = get_db()
    uid = session["user_id"]
    f = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    if not f:
        flash("File not found.", "danger")
        return redirect(url_for("dashboard"))

    if f["receiver_id"] != uid and f["owner_id"] != uid:
        flash("Unauthorized.", "danger")
        return redirect(url_for("dashboard"))

    action = request.args.get("action", "download")

    if request.method == "POST":
        entered_password = request.form.get("file_password", "")
        if check_password_hash(f["file_password_hash"], entered_password):
            session[f"file_access_{file_id}"] = True
            if action == "preview":
                return redirect(url_for("preview", file_id=file_id))
            return redirect(url_for("download", file_id=file_id))
        else:
            log_access(db, file_id, uid, action, "denied - wrong file password")
            flash("Wrong file password.", "danger")

    return render_template("verify_password.html", file=f, action=action)


# ── Routes: Download ─────────────────────────────────────────────

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    db = get_db()
    uid = session["user_id"]
    f = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    if not f:
        flash("File not found.", "danger")
        return redirect(url_for("dashboard"))

    if f["receiver_id"] != uid and f["owner_id"] != uid:
        log_access(db, file_id, uid, "download", "denied - unauthorized")
        flash("You are not authorized.", "danger")
        return redirect(url_for("dashboard"))

    # Check if revoked
    if f["is_revoked"]:
        log_access(db, file_id, uid, "download", "denied - revoked")
        flash("Access denied: file access has been revoked by the owner.", "danger")
        return redirect(url_for("dashboard"))

    # Check expiry
    now = datetime.utcnow()
    expiry = datetime.strptime(f["expiry_time"], "%Y-%m-%d %H:%M:%S")
    if f["receiver_id"] == uid and now > expiry:
        log_access(db, file_id, uid, "download", "denied - expired")
        flash("Access denied: this file has expired.", "danger")
        return redirect(url_for("dashboard"))

    # Check if download is allowed
    if f["receiver_id"] == uid and not f["allow_download"]:
        log_access(db, file_id, uid, "download", "denied - downloads disabled")
        flash("Download disabled. You can only preview this file.", "warning")
        return redirect(url_for("dashboard"))

    # Check download limit
    if f["receiver_id"] == uid and f["max_downloads"] > 0 and f["current_downloads"] >= f["max_downloads"]:
        log_access(db, file_id, uid, "download", "denied - download limit reached")
        flash(f"Download limit reached ({f['max_downloads']} downloads).", "danger")
        return redirect(url_for("dashboard"))

    # Check file password
    if f["file_password_hash"] and not session.get(f"file_access_{file_id}"):
        return redirect(url_for("verify_password", file_id=file_id, action="download"))

    # Get receiver's private key to unwrap AES key
    user = db.execute("SELECT rsa_private_key FROM users WHERE id = ?", (uid,)).fetchone()

    # For the owner, we need receiver's key — but owner stored the file.
    # We re-encrypt AES key for receiver only. Owner uses a fallback:
    # decrypt using receiver's key if owner == receiver access isn't possible,
    # so for owner download, we store a copy. Simpler: owner can't download
    # their own file through RSA path. Let's handle this:
    if f["owner_id"] == uid:
        # Owner re-encrypts for themselves — but we didn't store that.
        # For simplicity, owner sees the file via receiver's perspective isn't possible.
        # Let owner download by re-reading with the receiver's private key?
        # Actually for a simple project, let owner use receiver's key stored in DB:
        receiver = db.execute("SELECT rsa_private_key FROM users WHERE id = ?", (f["receiver_id"],)).fetchone()
        private_key = receiver["rsa_private_key"]
    else:
        private_key = user["rsa_private_key"]

    try:
        decrypted = decrypt_file_data(f, private_key)
    except Exception:
        log_access(db, file_id, uid, "download", "denied - decryption failed")
        flash("Decryption failed. Key mismatch.", "danger")
        return redirect(url_for("dashboard"))

    # Verify SHA-256 integrity
    computed_hash = hashlib.sha256(decrypted).hexdigest()
    if computed_hash != f["file_hash"]:
        log_access(db, file_id, uid, "download", "denied - integrity failure")
        flash("File integrity check failed! File may be tampered.", "danger")
        return redirect(url_for("dashboard"))

    # Verify digital signature
    owner = db.execute("SELECT rsa_public_key, username FROM users WHERE id = ?", (f["owner_id"],)).fetchone()
    sig_valid = verify_signature(f["file_hash"], f["digital_signature"], owner["rsa_public_key"])

    # Increment download counter
    if f["receiver_id"] == uid:
        db.execute("UPDATE files SET current_downloads = current_downloads + 1 WHERE id = ?", (file_id,))
        db.commit()

    log_access(db, file_id, uid, "download", "success")
    session.pop(f"file_access_{file_id}", None)

    # Self-destruct: delete file after first download
    if f["self_destruct"] and f["receiver_id"] == uid:
        filepath = os.path.join(UPLOAD_FOLDER, f["stored_name"])
        if os.path.exists(filepath):
            os.remove(filepath)
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        db.commit()
        flash("This file has self-destructed after download.", "info")

    if not sig_valid:
        flash("Warning: Digital signature verification failed!", "warning")

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix="_" + f["original_name"])
    tmp.write(decrypted)
    tmp.close()
    return send_file(tmp.name, as_attachment=True, download_name=f["original_name"])


# ── Routes: File Preview ─────────────────────────────────────────

@app.route("/preview/<int:file_id>")
@login_required
def preview(file_id):
    db = get_db()
    uid = session["user_id"]
    f = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    if not f:
        flash("File not found.", "danger")
        return redirect(url_for("dashboard"))

    if f["receiver_id"] != uid and f["owner_id"] != uid:
        flash("Unauthorized.", "danger")
        return redirect(url_for("dashboard"))

    # Check if revoked
    if f["is_revoked"]:
        flash("Access denied: file access has been revoked.", "danger")
        return redirect(url_for("dashboard"))

    now = datetime.utcnow()
    expiry = datetime.strptime(f["expiry_time"], "%Y-%m-%d %H:%M:%S")
    if f["receiver_id"] == uid and now > expiry:
        flash("Access denied: file expired.", "danger")
        return redirect(url_for("dashboard"))

    # Check view limit
    if f["receiver_id"] == uid and f["max_views"] > 0 and f["current_views"] >= f["max_views"]:
        log_access(db, file_id, uid, "preview", "denied - view limit reached")
        flash(f"View limit reached ({f['max_views']} views).", "danger")
        return redirect(url_for("dashboard"))

    if f["file_password_hash"] and not session.get(f"file_access_{file_id}"):
        return redirect(url_for("verify_password", file_id=file_id, action="preview"))

    if not is_previewable(f["mime_type"]):
        flash("This file type cannot be previewed.", "info")
        return redirect(url_for("dashboard"))

    # Get private key
    if f["owner_id"] == uid:
        receiver = db.execute("SELECT rsa_private_key FROM users WHERE id = ?", (f["receiver_id"],)).fetchone()
        private_key = receiver["rsa_private_key"]
    else:
        user = db.execute("SELECT rsa_private_key FROM users WHERE id = ?", (uid,)).fetchone()
        private_key = user["rsa_private_key"]

    try:
        decrypted = decrypt_file_data(f, private_key)
    except Exception:
        flash("Decryption failed.", "danger")
        return redirect(url_for("dashboard"))

    if hashlib.sha256(decrypted).hexdigest() != f["file_hash"]:
        flash("Integrity check failed!", "danger")
        return redirect(url_for("dashboard"))

    # Verify signature
    owner = db.execute("SELECT rsa_public_key FROM users WHERE id = ?", (f["owner_id"],)).fetchone()
    sig_valid = verify_signature(f["file_hash"], f["digital_signature"], owner["rsa_public_key"])

    # Increment view counter
    if f["receiver_id"] == uid:
        db.execute("UPDATE files SET current_views = current_views + 1 WHERE id = ?", (file_id,))
        db.commit()

    log_access(db, file_id, uid, "preview", "success")
    session.pop(f"file_access_{file_id}", None)

    # Self-destruct after first view
    if f["self_destruct"] and f["receiver_id"] == uid:
        db.execute("UPDATE files SET is_revoked = 1 WHERE id = ?", (file_id,))
        db.commit()

    preview_data = {}
    mime = f["mime_type"]
    if mime.startswith("image/"):
        preview_data["type"] = "image"
        preview_data["data"] = f"data:{mime};base64,{base64.b64encode(decrypted).decode()}"
    elif mime.startswith("text/") or mime in ("application/json", "application/xml"):
        preview_data["type"] = "text"
        try:
            preview_data["data"] = decrypted.decode("utf-8")
        except UnicodeDecodeError:
            preview_data["data"] = decrypted.decode("latin-1")
    elif mime == "application/pdf":
        preview_data["type"] = "pdf"
        preview_data["data"] = f"data:application/pdf;base64,{base64.b64encode(decrypted).decode()}"

    return render_template("preview.html", file=f, preview=preview_data, sig_valid=sig_valid)


# ── Routes: Crypto Info (show user's keys) ────────────────────────

@app.route("/crypto_info")
@login_required
def crypto_info():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template("crypto_info.html", user=user)


# ── Routes: Access Logs ──────────────────────────────────────────

@app.route("/logs")
@login_required
def logs():
    db = get_db()
    uid = session["user_id"]
    rows = db.execute("""
        SELECT al.*, f.original_name, u.username
        FROM access_logs al
        JOIN files f ON al.file_id = f.id
        JOIN users u ON al.user_id = u.id
        WHERE f.owner_id = ? OR al.user_id = ?
        ORDER BY al.timestamp DESC
        LIMIT 100
    """, (uid, uid)).fetchall()

    # Verify HMAC integrity of each log
    log_list = []
    for row in rows:
        log_msg = f"{row['file_id']}|{row['user_id']}|{row['action']}|{row['status']}|{row['ip_address']}|{row['timestamp']}"
        hmac_valid = verify_hmac(log_msg, row["hmac_hash"], HMAC_SECRET) if row["hmac_hash"] else None
        log_list.append({"row": row, "hmac_valid": hmac_valid})

    return render_template("logs.html", logs=log_list)


# ── Routes: Revoke Access ───────────────────────────────────────

@app.route("/revoke/<int:file_id>", methods=["POST"])
@login_required
def revoke_access(file_id):
    db = get_db()
    f = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not f:
        flash("File not found.", "danger")
    elif f["owner_id"] != session["user_id"]:
        flash("Only the file owner can revoke access.", "danger")
    else:
        db.execute("UPDATE files SET is_revoked = 1 WHERE id = ?", (file_id,))
        db.commit()
        log_access(db, file_id, session["user_id"], "revoke", "success")
        flash(f"Access to '{f['original_name']}' has been revoked.", "success")
    return redirect(url_for("dashboard"))


# ══════════════════════════════════════════════════════════════════
# ADMIN PANEL
# ══════════════════════════════════════════════════════════════════

@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    files = db.execute("""
        SELECT f.*, o.username AS owner_name, r.username AS receiver_name
        FROM files f
        JOIN users o ON f.owner_id = o.id
        JOIN users r ON f.receiver_id = r.id
        ORDER BY f.created_at DESC
    """).fetchall()
    logs = db.execute("""
        SELECT al.*, f.original_name, u.username
        FROM access_logs al
        JOIN files f ON al.file_id = f.id
        JOIN users u ON al.user_id = u.id
        ORDER BY al.timestamp DESC
        LIMIT 50
    """).fetchall()

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    total_users = len(users)
    total_files = len(files)
    active_files = sum(1 for f in files if f["expiry_time"] > now)
    total_size = sum(f["file_size"] for f in files)

    return render_template(
        "admin.html",
        users=users, files=files, logs=logs, now=now,
        total_users=total_users, total_files=total_files,
        active_files=active_files, total_size=format_size(total_size),
    )


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash("User not found.", "danger")
    elif user["is_admin"]:
        flash("Cannot delete admin.", "danger")
    else:
        user_files = db.execute("SELECT stored_name FROM files WHERE owner_id = ?", (user_id,)).fetchall()
        for uf in user_files:
            path = os.path.join(UPLOAD_FOLDER, uf["stored_name"])
            if os.path.exists(path):
                os.remove(path)
        db.execute("DELETE FROM access_logs WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM files WHERE owner_id = ? OR receiver_id = ?", (user_id, user_id))
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        flash(f"User '{user['username']}' deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_file/<int:file_id>", methods=["POST"])
@admin_required
def admin_delete_file(file_id):
    db = get_db()
    f = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not f:
        flash("File not found.", "danger")
    else:
        path = os.path.join(UPLOAD_FOLDER, f["stored_name"])
        if os.path.exists(path):
            os.remove(path)
        db.execute("DELETE FROM access_logs WHERE file_id = ?", (file_id,))
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        db.commit()
        flash(f"File '{f['original_name']}' deleted.", "success")
    return redirect(url_for("admin_dashboard"))


# ── Run ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
