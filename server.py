import os, re, time, threading, secrets
from functools import wraps

import pyotp
from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
import jwt          # PyJWT for JWT handling
import hashlib

# 1. App & extensions
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///securechat.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET"] = os.getenv("JWT_SECRET", secrets.token_hex(32))
app.config["JWT_EXPIRY_SECONDS"] = int(os.getenv("JWT_EXPIRY_SECONDS", 3600))

# (R21) Offline-queue limits
MAX_QUEUE_SIZE = 200          # messages per user
MAX_QUEUE_AGE_DAYS = 30       # hard ceiling even if TTL not expired
MAX_MESSAGE_BYTES = 10 * 1024 # 10 KB ciphertext cap (DoS protection, R22)

db = SQLAlchemy(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],          # only apply per-route limits
    storage_uri="memory://",
)


# 2. Database models
class User(db.Model):
    __tablename__ = "users"
    username   = db.Column(db.String(64), primary_key=True)
    pw_hash    = db.Column(db.LargeBinary, nullable=False)
    salt       = db.Column(db.LargeBinary, nullable=False)
    otp_secret = db.Column(db.String(64),  nullable=False)
    pub_key    = db.Column(db.Text,        nullable=False)


class FriendRequest(db.Model):
    __tablename__ = "friend_requests"
    id       = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sender   = db.Column(db.String(64), nullable=False)
    receiver = db.Column(db.String(64), nullable=False)
    db.UniqueConstraint("sender", "receiver")


class Friendship(db.Model):
    __tablename__ = "friendships"
    id      = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_a  = db.Column(db.String(64), nullable=False)
    user_b  = db.Column(db.String(64), nullable=False)
    db.UniqueConstraint("user_a", "user_b")


class Block(db.Model):
    __tablename__ = "blocks"
    id      = db.Column(db.Integer, primary_key=True, autoincrement=True)
    blocker = db.Column(db.String(64), nullable=False)
    blocked = db.Column(db.String(64), nullable=False)
    db.UniqueConstraint("blocker", "blocked")


class OfflineMessage(db.Model):
    __tablename__ = "offline_messages"
    id         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sender     = db.Column(db.String(64), nullable=False)
    receiver   = db.Column(db.String(64), nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    ad         = db.Column(db.Text, nullable=False)
    ttl        = db.Column(db.Integer, nullable=False)
    queued_at  = db.Column(db.Float, nullable=False, default=time.time)
    expiry     = db.Column(db.Float, nullable=False)


class RevokedToken(db.Model):
    """JWT blacklist — stores jti (JWT ID) of logged-out tokens."""
    __tablename__ = "revoked_tokens"
    jti        = db.Column(db.String(64), primary_key=True)
    revoked_at = db.Column(db.Float, nullable=False, default=time.time)


# 3. Helpers

PASSWORD_RE = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=]).{10,72}$'
)

def hash_pw(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)


def _is_friend(user_a: str, user_b: str) -> bool:
    return Friendship.query.filter(
        ((Friendship.user_a == user_a) & (Friendship.user_b == user_b)) |
        ((Friendship.user_a == user_b) & (Friendship.user_b == user_a))
    ).first() is not None


def _is_blocked(blocker: str, blocked: str) -> bool:
    return Block.query.filter_by(blocker=blocker, blocked=blocked).first() is not None


def _make_token(username: str) -> tuple[str, str]:
    """Return (JWT string, jti) for the given user."""
    jti = secrets.token_hex(16)
    payload = {
        "sub": username,
        "jti": jti,
        "iat": time.time(),
        "exp": time.time() + app.config["JWT_EXPIRY_SECONDS"],
    }
    token = jwt.encode(payload, app.config["JWT_SECRET"], algorithm="HS256")
    return token, jti


def require_auth(f):
    """Decorator: validates Bearer JWT, populates g.username."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        raw = auth[7:]
        try:
            payload = jwt.decode(raw, app.config["JWT_SECRET"], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        # Check blacklist (R3)
        if RevokedToken.query.get(payload["jti"]):
            return jsonify({"error": "Token revoked"}), 401

        g.username = payload["sub"]
        g.jti = payload["jti"]
        return f(*args, **kwargs)
    return wrapper



# 4. Background cleanup worker  (R12, R21)

def _cleanup_worker():
    """Runs every 5 minutes. Deletes expired and over-age messages."""
    while True:
        time.sleep(300)
        try:
            with app.app_context():
                now = time.time()
                cutoff = now - MAX_QUEUE_AGE_DAYS * 86400
                deleted = OfflineMessage.query.filter(
                    (OfflineMessage.expiry < now) |
                    (OfflineMessage.queued_at < cutoff)
                ).delete(synchronize_session=False)
                db.session.commit()
                if deleted:
                    app.logger.info(f"[cleanup] Removed {deleted} stale offline messages")
        except Exception as exc:
            app.logger.error(f"[cleanup] Error: {exc}")



# 5. Routes – Registration & Authentication (R1, R2, R3)
@app.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    # (R1) Register: username + password (complexity enforced) + pub_key → OTP secret.
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password", "")
    pub_key  = data.get("pub_key", "")

    if not username or not password or not pub_key:
        return jsonify({"error": "Missing fields"}), 400
    if len(username) > 64:
        return jsonify({"error": "Username too long"}), 400
    if not re.match(r'^[A-Za-z0-9_\-]+$', username):
        return jsonify({"error": "Invalid username characters"}), 400
    if not PASSWORD_RE.match(password):
        return jsonify({
            "error": (
                "Password must be 10–72 chars and contain at least one "
                "uppercase letter, lowercase letter, digit, and special character."
            )
        }), 400
    if User.query.get(username):
        return jsonify({"error": "Username already exists"}), 409

    salt = os.urandom(16)
    user = User(
        username=username,
        pw_hash=hash_pw(password, salt),
        salt=salt,
        otp_secret=pyotp.random_base32(),
        pub_key=pub_key,
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"otp_secret": user.otp_secret}), 201


@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    # (R2) Login: password + OTP → signed JWT.
    data = request.get_json(silent=True) or {}
    user = User.query.get(data.get("username", ""))
    if (
        not user
        or hash_pw(data.get("password", ""), user.salt) != user.pw_hash
        or not pyotp.TOTP(user.otp_secret).verify(str(data.get("otp", "")))
    ):
        return jsonify({"error": "Invalid credentials"}), 401

    token, _ = _make_token(user.username)
    return jsonify({"token": token})


@app.route("/logout", methods=["POST"])
@require_auth
def logout():
    """(R3) Logout: blacklist current JWT so it can no longer be used."""
    db.session.add(RevokedToken(jti=g.jti))
    db.session.commit()
    return jsonify({"msg": "Logged out"})



# 6. Routes – Contact / Friend Management  (R13, R14, R15)
@app.route("/friend_request", methods=["POST"])
@require_auth
@limiter.limit("30 per minute")
def friend_request():
    # (R13) Send a friend request.
    target = (request.get_json(silent=True) or {}).get("target", "").strip()
    sender = g.username
    if not User.query.get(target):
        return jsonify({"error": "User not found"}), 404
    if target == sender:
        return jsonify({"error": "Cannot friend yourself"}), 400
    if _is_blocked(target, sender):
        # Silently succeed so sender doesn't learn they are blocked (R15)
        return jsonify({"msg": "Sent"})
    if _is_friend(sender, target):
        return jsonify({"error": "Already friends"}), 409
    if FriendRequest.query.filter_by(sender=sender, receiver=target).first():
        return jsonify({"error": "Request already pending"}), 409

    db.session.add(FriendRequest(sender=sender, receiver=target))
    db.session.commit()
    return jsonify({"msg": "Sent"})


@app.route("/accept_friend", methods=["POST"])
@require_auth
def accept_friend():
    # (R13) Accept a pending friend request.
    friend = (request.get_json(silent=True) or {}).get("friend", "").strip()
    user = g.username
    req = FriendRequest.query.filter_by(sender=friend, receiver=user).first()
    if not req:
        return jsonify({"error": "No such request"}), 404
    db.session.delete(req)
    db.session.add(Friendship(user_a=user, user_b=friend))
    db.session.commit()
    return jsonify({"msg": "Accepted"})


@app.route("/decline_friend", methods=["POST"])
@require_auth
def decline_friend():
    # (R14) Decline an incoming friend request.
    friend = (request.get_json(silent=True) or {}).get("friend", "").strip()
    req = FriendRequest.query.filter_by(sender=friend, receiver=g.username).first()
    if not req:
        return jsonify({"error": "No such request"}), 404
    db.session.delete(req)
    db.session.commit()
    return jsonify({"msg": "Declined"})


@app.route("/cancel_friend_request", methods=["POST"])
@require_auth
def cancel_friend_request():
    # (R14) Cancel an outgoing friend request before it is accepted.
    target = (request.get_json(silent=True) or {}).get("target", "").strip()
    req = FriendRequest.query.filter_by(sender=g.username, receiver=target).first()
    if not req:
        return jsonify({"error": "No such request"}), 404
    db.session.delete(req)
    db.session.commit()
    return jsonify({"msg": "Cancelled"})


@app.route("/block_user", methods=["POST"])
@require_auth
def block_user():
    # (R15) Block a user: drops any pending request and prevents future contact.
    target = (request.get_json(silent=True) or {}).get("target", "").strip()
    if not target or target == g.username:
        return jsonify({"error": "Invalid target"}), 400
    if not _is_blocked(g.username, target):
        db.session.add(Block(blocker=g.username, blocked=target))
    # Remove any pending friend request from that user
    FriendRequest.query.filter_by(sender=target, receiver=g.username).delete()
    db.session.commit()
    return jsonify({"msg": "Blocked"})


@app.route("/unblock_user", methods=["POST"])
@require_auth
def unblock_user():
    # (R15) Unblock a previously blocked user.
    target = (request.get_json(silent=True) or {}).get("target", "").strip()
    Block.query.filter_by(blocker=g.username, blocked=target).delete()
    db.session.commit()
    return jsonify({"msg": "Unblocked"})



# Routes – Messaging  (R16, R17, R20, R21, R22)

@app.route("/send_message", methods=["POST"])
@require_auth
@limiter.limit("120 per minute")
def send_message():
    # (R16, R17, R21, R22) Send an encrypted message to a friend.
    data = request.get_json(silent=True) or {}
    sender   = g.username
    receiver = data.get("receiver", "").strip()
    ciphertext = data.get("ciphertext", "")
    ad         = data.get("ad", "")
    ttl        = int(data.get("ttl", 60))

    # (R22) Payload size cap
    if len(ciphertext.encode()) > MAX_MESSAGE_BYTES:
        return jsonify({"error": "Payload too large"}), 413

    if not receiver or not ciphertext or not ad:
        return jsonify({"error": "Missing fields"}), 400

    # (R15) Honour block list in both directions
    if _is_blocked(receiver, sender) or _is_blocked(sender, receiver):
        return jsonify({"error": "Forbidden"}), 403

    # (R16) Friends-only messaging
    if not _is_friend(sender, receiver):
        return jsonify({"error": "Not friends"}), 403

    # (R21) Per-user queue size cap
    queue_size = OfflineMessage.query.filter_by(receiver=receiver).count()
    if queue_size >= MAX_QUEUE_SIZE:
        return jsonify({"error": "Receiver queue full"}), 429

    expiry = time.time() + max(1, min(ttl, 2_592_000))  # cap at 30 days
    msg = OfflineMessage(
        sender=sender,
        receiver=receiver,
        ciphertext=ciphertext,
        ad=ad,
        ttl=ttl,
        queued_at=time.time(),
        expiry=expiry,
    )
    db.session.add(msg)
    db.session.commit()
    return jsonify({"status": "Sent", "msg_id": msg.id})  # (R17)


@app.route("/sync/<username>", methods=["GET"])
@require_auth
def sync(username):
    # (R20) Fetch offline queue and pending friend requests. Clears fetched messages.
    if g.username != username:
        return jsonify({"error": "Forbidden"}), 403

    now = time.time()
    msgs = OfflineMessage.query.filter(
        OfflineMessage.receiver == username,
        OfflineMessage.expiry > now,
    ).all()

    payload = [
        {
            "msg_id":     m.id,
            "sender":     m.sender,
            "ciphertext": m.ciphertext,
            "ad":         m.ad,
            "ttl":        m.ttl,
        }
        for m in msgs
    ]

    # Delete delivered messages
    ids = [m.id for m in msgs]
    if ids:
        OfflineMessage.query.filter(OfflineMessage.id.in_(ids)).delete(
            synchronize_session=False
        )

    # Pending friend requests
    reqs = [r.sender for r in FriendRequest.query.filter_by(receiver=username).all()]

    db.session.commit()
    return jsonify({"messages": payload, "friend_requests": reqs})


@app.route("/get_key/<username>", methods=["GET"])
@require_auth
def get_key(username):
    user = User.query.get(username)
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"pub_key": user.pub_key})



# 7. App init

def create_app():
    with app.app_context():
        db.create_all()
    t = threading.Thread(target=_cleanup_worker, daemon=True)
    t.start()
    return app


if __name__ == "__main__":
    create_app()
    # Production: use Gunicorn + TLS certificates
    # gunicorn -w 4 --certfile cert.pem --keyfile key.pem "server:app"
    # (4.2) Transport security: In production use ssl_context=('cert.pem', 'key.pem')
    app.run(port=5000, debug=False)
