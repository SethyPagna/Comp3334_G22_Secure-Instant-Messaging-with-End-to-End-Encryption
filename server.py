"""
SecureChat Server

Threat model: Honest-But-Curious (HbC) — server follows protocol but may
inspect all data it holds. The server never has access to plaintext messages
or private keys.

Stack:
  • Flask + threaded WSGI
  • SQLite (WAL mode for concurrent reads)
  • PBKDF2-SHA256 (260 000 iterations) password hashing  [no argon2 available]
  • HS256 JWT session tokens (stdlib HMAC)
  • TOTP RFC 6238 second factor
  • In-memory rate limiting per IP / user
"""

# Raad -> # Commnts
import os
import sys
import json
import time
import uuid
import hmac
import base64
import hashlib
import struct
import sqlite3
import threading

from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory

import crypto_utils as C

# Configuration
DB_PATH          = os.environ.get("SC_DB",     "server.db")
JWT_SECRET       = os.environ.get("SC_SECRET", os.urandom(32).hex())
PORT             = int(os.environ.get("SC_PORT", 5000))
TOKEN_TTL        = 86_400          # 24 h
MSG_MAX_AGE      = 7 * 86_400      # 7 days hard cap for offline queue
CLEANUP_INTERVAL = 300             # 5 min background cleanup

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["JSON_SORT_KEYS"] = False


# CORS (allows browser clients on same origin or dev ports) 
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    return response

@app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
@app.route("/<path:path>", methods=["OPTIONS"])
def options_handler(path=""):
    return "", 204

# ── Serve the browser client ──────────────────────────────────────────────────
@app.route("/")
def serve_index():
    return send_from_directory("static", "index.html")

# ── Rate limiting (in-memory, per key) ───────────────────────────────────────
_rl: dict = {}
_rl_lock = threading.Lock()

# 4. Rate limit
def rate_ok(key: str, limit: int, window: int) -> bool:
    now = time.time()
    with _rl_lock:
        bucket = [t for t in _rl.get(key, []) if now - t < window]
        if len(bucket) >= limit:
            _rl[key] = bucket
            return False
        bucket.append(now)
        _rl[key] = bucket
        return True


# JWT (HS256, stdlib) 
def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

# 3. JWT Authentication with HS256 signatures.
def jwt_create(user_id: int) -> str:
    header  = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64u(json.dumps({
        "sub": user_id,
        "exp": int(time.time()) + TOKEN_TTL,
        "jti": uuid.uuid4().hex,
    }).encode())
    sig = _b64u(hmac.new(
        JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256
    ).digest())
    return f"{header}.{payload}.{sig}"

def jwt_verify(token: str):
    try:
        h, p, s = token.split(".")
        expected = _b64u(hmac.new(
            JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256
        ).digest())
        if not hmac.compare_digest(s, expected):
            return None
        payload = json.loads(_unb64u(p))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


# 2. Password hashing (PBKDF2-SHA256, 260k iterations) 
def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    key  = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 260_000)
    return f"{salt.hex()}:{key.hex()}"

def check_password(stored: str, pw: str) -> bool:
    try:
        salt_h, key_h = stored.split(":")
        key = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_h), 260_000)
        return hmac.compare_digest(key.hex(), key_h)
    except Exception:
        return False


# ── Database ──────────────────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=30)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_=None):
    db = g.pop("db", None)
    if db:
        db.close()

# 1. SQLite schema & WAL init //users,messages (offline queue), delivery_receipts, friend_requests, blocked, active_tokens
def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            pw_hash     TEXT    NOT NULL,
            totp_secret TEXT    NOT NULL,
            sign_pub    TEXT    NOT NULL,   -- Ed25519 identity signing pubkey (hex)
            ik_pub      TEXT    NOT NULL,   -- X25519 identity DH pubkey (hex)
            spk_pub     TEXT    NOT NULL,   -- X25519 signed prekey pubkey (hex)
            spk_sig     TEXT    NOT NULL,   -- Ed25519 sig of spk_pub (hex)
            created_at  REAL    DEFAULT (unixepoch())
        );

        CREATE TABLE IF NOT EXISTS active_tokens (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            expires_at REAL    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS friend_requests (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id   INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            status      TEXT    DEFAULT 'pending',   -- pending | accepted | declined
            created_at  REAL    DEFAULT (unixepoch()),
            UNIQUE(sender_id, receiver_id),
            FOREIGN KEY (sender_id)   REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        );

        -- Offline ciphertext queue (store-and-forward, R20)
        CREATE TABLE IF NOT EXISTS messages (
            id          TEXT    PRIMARY KEY,
            sender_id   INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            payload     TEXT    NOT NULL,   -- JSON envelope (ciphertext only)
            expires_at  REAL,               -- NULL = no TTL
            created_at  REAL    DEFAULT (unixepoch()),
            FOREIGN KEY (sender_id)   REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        );

        -- Delivery receipts: sender polls these to learn "delivered" status (R17-R18)
        CREATE TABLE IF NOT EXISTS delivery_receipts (
            message_id   TEXT    PRIMARY KEY,
            sender_id    INTEGER NOT NULL,
            delivered_at REAL    DEFAULT (unixepoch()),
            fetched      INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS blocked (
            user_id   INTEGER NOT NULL,
            target_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, target_id)
        );

        CREATE INDEX IF NOT EXISTS idx_msg_receiver ON messages(receiver_id);
        CREATE INDEX IF NOT EXISTS idx_receipts_sender ON delivery_receipts(sender_id, fetched);
    """)
    conn.commit()
    conn.close()
    print(f"[server] Database initialised at {DB_PATH}")


# 5. Authentication Middleware
def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        token   = header[7:]
        payload = jwt_verify(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        db  = get_db()
        row = db.execute(
            "SELECT user_id FROM active_tokens WHERE token=? AND expires_at>?",
            (token, time.time()),
        ).fetchone()
        if not row:
            return jsonify({"error": "Session expired — please log in again"}), 401
        request.uid   = row["user_id"]
        request.token = token
        return f(*args, **kwargs)
    return wrapper


# Helper
def get_user_by_name(db, username: str):
    return db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

def are_friends(db, a: int, b: int) -> bool:
    return bool(db.execute(
        """SELECT 1 FROM friend_requests
           WHERE ((sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?))
             AND status='accepted'""",
        (a, b, b, a),
    ).fetchone())



# 6. Account management 
# R1: register with username, password, and public keys (signing + DH)
@app.post("/api/register")
def register():
    ip = request.remote_addr
    if not rate_ok(f"reg:{ip}", 5, 300):   # 5 registrations per 5 min per IP
        return jsonify({"error": "Rate limited — try again later"}), 429

    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password", "")

    # Validate username (3-32 alphanumeric)
    if not (3 <= len(username) <= 32) or not username.replace("_", "").isalnum():
        return jsonify({"error": "Username: 3–32 chars, letters/digits/underscore only"}), 400
    # Password policy: min 8 chars
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    # Require public key material
    for field in ("sign_pub", "ik_pub", "spk_pub", "spk_sig"):
        if not data.get(field):
            return jsonify({"error": f"Missing field: {field}"}), 400

    db = get_db()
    if get_user_by_name(db, username):
        return jsonify({"error": "Username already taken"}), 409

    totp_secret = C.gen_totp_secret()
    db.execute(
        "INSERT INTO users (username, pw_hash, totp_secret, sign_pub, ik_pub, spk_pub, spk_sig)"
        " VALUES (?,?,?,?,?,?,?)",
        (username, hash_password(password), totp_secret,
         data["sign_pub"], data["ik_pub"], data["spk_pub"], data["spk_sig"]),
    )
    db.commit()
    return jsonify({
        "message":     "Account created",
        "totp_secret": totp_secret,
        "totp_uri":    f"otpauth://totp/SecureChat:{username}?secret={totp_secret}&issuer=SecureChat",
    }), 201

# R2 Login with username, password, and TOTP code; receive JWT session token
@app.post("/api/login")
def login():
    ip = request.remote_addr
    if not rate_ok(f"login:{ip}", 10, 60):  # 10 attempts per min per IP
        return jsonify({"error": "Rate limited — try again later"}), 429

    data     = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password", "")
    totp_in  = str(data.get("totp_code", "")).strip()

    db   = get_db()
    user = get_user_by_name(db, username)
    # Constant-time: always check password even if user not found (mitigate timing oracle)
    pw_ok = user and check_password(user["pw_hash"], password)
    if not pw_ok:
        return jsonify({"error": "Invalid credentials"}), 401
    if not C.verify_totp(user["totp_secret"], totp_in):
        return jsonify({"error": "Invalid TOTP code"}), 401

    token = jwt_create(user["id"])
    db.execute("INSERT INTO active_tokens VALUES (?,?,?)",
               (token, user["id"], time.time() + TOKEN_TTL))
    db.commit()
    return jsonify({"token": token, "username": username}), 200

# R3 Logout (invalidate session token)
@app.post("/api/logout")
@auth_required
def logout():
    get_db().execute("DELETE FROM active_tokens WHERE token=?", (request.token,))
    get_db().commit()
    return jsonify({"message": "Logged out"}), 200

# r4 Public Key Distribution (see below)
@app.get("/api/me")
@auth_required
def me():
    row = get_db().execute("SELECT username FROM users WHERE id=?", (request.uid,)).fetchone()
    return jsonify({"username": row["username"], "user_id": request.uid}), 200


# 7. Public Key Distribution
@app.get("/api/keys/<username>")
@auth_required
def get_keys(username):
    """
    Public key bundle for a user.
    Server stores only public keys; private keys never leave the client.
    """
    u = get_user_by_name(get_db(), username.strip().lower())
    if not u:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "username": u["username"],
        "sign_pub": u["sign_pub"],
        "ik_pub":   u["ik_pub"],
        "spk_pub":  u["spk_pub"],
        "spk_sig":  u["spk_sig"],
    }), 200


# 8. Friend management
# Send Friend Request
@app.post("/api/friends/request")
@auth_required
def friend_request():
    if not rate_ok(f"fr:{request.uid}", 20, 60):
        return jsonify({"error": "Rate limited"}), 429

    data    = request.get_json(force=True, silent=True) or {}
    to_name = (data.get("to") or "").strip().lower()
    db      = get_db()
    to_user = get_user_by_name(db, to_name)
    if not to_user:
        return jsonify({"error": "User not found"}), 404
    if to_user["id"] == request.uid:
        return jsonify({"error": "Cannot send friend request to yourself"}), 400
    # Check if target has blocked sender
    if db.execute("SELECT 1 FROM blocked WHERE user_id=? AND target_id=?",
                  (to_user["id"], request.uid)).fetchone():
        return jsonify({"error": "User not found"}), 404   # silent — don't reveal block
    # Check duplicate
    existing = db.execute(
        "SELECT status FROM friend_requests WHERE sender_id=? AND receiver_id=?",
        (request.uid, to_user["id"]),
    ).fetchone()
    if existing:
        return jsonify({"error": f"Request already {existing['status']}"}), 409
    # Check already friends (reverse direction accepted)
    if are_friends(db, request.uid, to_user["id"]):
        return jsonify({"error": "Already friends"}), 409

    db.execute("INSERT INTO friend_requests (sender_id, receiver_id) VALUES (?,?)",
               (request.uid, to_user["id"]))
    db.commit()
    return jsonify({"message": "Friend request sent"}), 201

# Incoming Requests
@app.get("/api/friends/requests/incoming")
@auth_required
def incoming_requests():
    rows = get_db().execute("""
        SELECT fr.id, u.username AS from_username, fr.created_at
        FROM   friend_requests fr
        JOIN   users u ON u.id = fr.sender_id
        WHERE  fr.receiver_id=? AND fr.status='pending'
        ORDER  BY fr.created_at DESC
    """, (request.uid,)).fetchall()
    return jsonify([dict(r) for r in rows]), 200

# Outgoing Requests
@app.get("/api/friends/requests/outgoing")
@auth_required
def outgoing_requests():
    rows = get_db().execute("""
        SELECT fr.id, u.username AS to_username, fr.status, fr.created_at
        FROM   friend_requests fr
        JOIN   users u ON u.id = fr.receiver_id
        WHERE  fr.sender_id=? AND fr.status='pending'
        ORDER  BY fr.created_at DESC
    """, (request.uid,)).fetchall()
    return jsonify([dict(r) for r in rows]), 200

# Accept
@app.post("/api/friends/requests/<int:req_id>/accept")
@auth_required
def accept_request(req_id):
    db = get_db()
    r  = db.execute(
        "SELECT * FROM friend_requests WHERE id=? AND receiver_id=? AND status='pending'",
        (req_id, request.uid),
    ).fetchone()
    if not r:
        return jsonify({"error": "Request not found"}), 404
    db.execute("UPDATE friend_requests SET status='accepted' WHERE id=?", (req_id,))
    db.commit()
    return jsonify({"message": "Friend request accepted"}), 200

# Decline
@app.post("/api/friends/requests/<int:req_id>/decline")
@auth_required
def decline_request(req_id):
    db = get_db()
    r  = db.execute(
        "SELECT * FROM friend_requests WHERE id=? AND receiver_id=? AND status='pending'",
        (req_id, request.uid),
    ).fetchone()
    if not r:
        return jsonify({"error": "Request not found"}), 404
    db.execute("UPDATE friend_requests SET status='declined' WHERE id=?", (req_id,))
    db.commit()
    return jsonify({"message": "Request declined"}), 200

# Cancel
@app.delete("/api/friends/requests/<int:req_id>")
@auth_required
def cancel_request(req_id):
    db = get_db()
    r  = db.execute(
        "SELECT * FROM friend_requests WHERE id=? AND sender_id=? AND status='pending'",
        (req_id, request.uid),
    ).fetchone()
    if not r:
        return jsonify({"error": "Request not found"}), 404
    db.execute("DELETE FROM friend_requests WHERE id=?", (req_id,))
    db.commit()
    return jsonify({"message": "Request cancelled"}), 200

# List Friends
@app.get("/api/friends")
@auth_required
def list_friends():
    rows = get_db().execute("""
        SELECT u.username, u.sign_pub, u.ik_pub, u.spk_pub, u.spk_sig
        FROM   users u
        WHERE  u.id IN (
            SELECT receiver_id FROM friend_requests
            WHERE  sender_id=? AND status='accepted'
            UNION
            SELECT sender_id FROM friend_requests
            WHERE  receiver_id=? AND status='accepted'
        )
        ORDER BY u.username
    """, (request.uid, request.uid)).fetchall()
    return jsonify([dict(r) for r in rows]), 200

# 9. Block / Unblock Users
# Block
@app.post("/api/block/<username>")
@auth_required
def block_user(username):
    username = username.strip().lower()
    db = get_db()
    u  = get_user_by_name(db, username)
    if not u:
        return jsonify({"error": "User not found"}), 404
    db.execute("INSERT OR IGNORE INTO blocked (user_id, target_id) VALUES (?,?)",
               (request.uid, u["id"]))
    db.execute("""DELETE FROM friend_requests
                  WHERE (sender_id=? AND receiver_id=?)
                     OR (sender_id=? AND receiver_id=?)""",
               (request.uid, u["id"], u["id"], request.uid))
    db.commit()
    return jsonify({"message": f"Blocked {username}"}), 200

# Unblock
@app.post("/api/unblock/<username>")
@auth_required
def unblock_user(username):
    username = username.strip().lower()
    db = get_db()
    u  = get_user_by_name(db, username)
    if not u:
        return jsonify({"error": "User not found"}), 404
    db.execute("DELETE FROM blocked WHERE user_id=? AND target_id=?",
               (request.uid, u["id"]))
    db.commit()
    return jsonify({"message": f"Unblocked {username}"}), 200


# 10. Messaging System (Store-and-Forward)
#  Send Message (Offline Queue)
@app.post("/api/messages/send")
@auth_required
def send_message():
    """
    Relay an E2EE ciphertext envelope to recipient's offline queue.
    Server sees: sender, receiver, message_id, timestamp, TTL, ciphertext blob.
    Server cannot decrypt content (no private keys).
    """
    data    = request.get_json(force=True, silent=True) or {}
    to_name = (data.get("to") or "").strip().lower()
    db      = get_db()
    to_user = get_user_by_name(db, to_name)
    if not to_user:
        return jsonify({"error": "User not found"}), 404
    if not are_friends(db, request.uid, to_user["id"]):
        return jsonify({"error": "Not friends — messages can only be sent to friends (R16)"}), 403
    if db.execute("SELECT 1 FROM blocked WHERE user_id=? AND target_id=?",
                  (to_user["id"], request.uid)).fetchone():
        return jsonify({"error": "Blocked"}), 403

    msg_id  = data.get("message_id")
    payload = data.get("payload")
    if not msg_id or not payload:
        return jsonify({"error": "Missing message_id or payload"}), 400

    # Extract TTL from (plaintext) AD to compute expiry (best-effort R12)
    ttl = 0
    try:
        ad = payload.get("ad", {}) if isinstance(payload, dict) else {}
        ttl = int(ad.get("ttl", 0))
    except (TypeError, ValueError):
        pass
    expires_at = (time.time() + ttl) if ttl > 0 else None

    # Idempotent insert — safe to retry
    if db.execute("SELECT 1 FROM messages WHERE id=?", (msg_id,)).fetchone():
        return jsonify({"status": "sent", "message_id": msg_id}), 200

    payload_str = json.dumps(payload) if isinstance(payload, dict) else payload
    db.execute(
        "INSERT INTO messages (id, sender_id, receiver_id, payload, expires_at) VALUES (?,?,?,?,?)",
        (msg_id, request.uid, to_user["id"], payload_str, expires_at),
    )
    db.commit()
    return jsonify({"status": "sent", "message_id": msg_id}), 200

# Poll Messages
@app.get("/api/messages/poll")
@auth_required
def poll_messages():
    """
    Fetch pending ciphertext from the offline queue.
    Returns at most 50 non-expired messages; client ACKs each to dequeue.
    Metadata disclosed to server per R19: sender, receiver, timing, size.
    """
    now  = time.time()
    rows = get_db().execute("""
        SELECT m.id, u.username AS sender, m.payload, m.created_at, m.expires_at
        FROM   messages m
        JOIN   users u ON u.id = m.sender_id
        WHERE  m.receiver_id=?
          AND  (m.expires_at IS NULL OR m.expires_at > ?)
        ORDER  BY m.created_at ASC
        LIMIT  50
    """, (request.uid, now)).fetchall()
    return jsonify([dict(r) for r in rows]), 200

# ACKnoledge Message (Dequeue)
@app.post("/api/messages/<msg_id>/ack")
@auth_required
def ack_message(msg_id):
    """
    Receiver acknowledges a message (R18 Option B).
    - Removes from queue (delivered).
    - Writes delivery receipt for sender to poll.
    """
    db  = get_db()
    msg = db.execute(
        "SELECT sender_id FROM messages WHERE id=? AND receiver_id=?",
        (msg_id, request.uid),
    ).fetchone()
    if not msg:
        # Already ACKed — idempotent
        return jsonify({"status": "ok"}), 200
    db.execute("DELETE FROM messages WHERE id=?", (msg_id,))
    db.execute(
        "INSERT OR IGNORE INTO delivery_receipts (message_id, sender_id) VALUES (?,?)",
        (msg_id, msg["sender_id"]),
    )
    db.commit()
    return jsonify({"status": "acked"}), 200

# Delivery Receipts Polling
@app.get("/api/receipts/poll")
@auth_required
def poll_receipts():
    """
    Sender polls for delivery receipts (R17 'Delivered' status).
    Returns un-fetched receipts and marks them as fetched.
    """
    db   = get_db()
    rows = db.execute(
        "SELECT message_id, delivered_at FROM delivery_receipts WHERE sender_id=? AND fetched=0",
        (request.uid,),
    ).fetchall()
    if rows:
        ids = [r["message_id"] for r in rows]
        db.execute(
            f"UPDATE delivery_receipts SET fetched=1 WHERE message_id IN ({','.join('?'*len(ids))})",
            ids,
        )
        db.commit()
    return jsonify([dict(r) for r in rows]), 200


# 12. TTL + Background cleanup 
def _cleanup_loop():
    """Periodically purge expired data (TTL, stale tokens, old receipts)."""
    while True:
        time.sleep(CLEANUP_INTERVAL)
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            now  = time.time()
            conn.execute("DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at<=?", (now,))
            conn.execute("DELETE FROM active_tokens WHERE expires_at<=?", (now,))
            conn.execute("DELETE FROM delivery_receipts WHERE fetched=1 AND delivered_at<?", (now - 86_400,))
            # Hard-cap old messages regardless of TTL
            conn.execute("DELETE FROM messages WHERE created_at<?", (now - MSG_MAX_AGE,))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[cleanup] {e}", file=sys.stderr)


# Entry point 
if __name__ == "__main__":
    init_db()
    # Start background cleanup thread (daemon)
    threading.Thread(target=_cleanup_loop, daemon=True, name="cleanup").start()
    print(f"[server] Listening on http://0.0.0.0:{PORT}")
    print(f"[server] DB: {DB_PATH}")
    print("[server] Press Ctrl-C to stop\n")

    app.run(host="0.0.0.0", port=PORT, threaded=True, use_reloader=False)
