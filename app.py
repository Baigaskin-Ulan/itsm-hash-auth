import hashlib
import logging
import secrets
import sqlite3
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import Flask, g, make_response, redirect, render_template, request, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=16 * 1024,
)
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")
csrf = CSRFProtect(app)

ph = PasswordHasher()
DUMMY_HASH = ph.hash("dummy-password-for-timing")

DB_PATH = "app.db"
COOKIE_NAME = "__Host-sid"
IDLE_TIMEOUT = 30 * 60
ABSOLUTE_TIMEOUT = 8 * 60 * 60
MIN_LEN = 15
MAX_LEN = 128

log = logging.getLogger("auth")
log.setLevel(logging.INFO)
handler = logging.FileHandler("auth.log", encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
log.addHandler(handler)


def audit(event, username):
    log.info("%s user=%r ip=%s", event, username, request.remote_addr)


with open("blocklist.txt", encoding="utf-8") as f:
    BLOCKLIST = {line.strip().lower() for line in f if line.strip()}


def password_error(username, password):
    """Return an error string if the new password breaks the policy, else None."""
    if not MIN_LEN <= len(password) <= MAX_LEN:
        return f"Password must be {MIN_LEN} to {MAX_LEN} characters long."
    if password.lower() in BLOCKLIST:
        return "This password is too common. Choose another one."
    if username.lower() in password.lower():
        return "Password must not contain the username."
    return None




def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()





def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    now = time.time()
    db = get_db()
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, last_seen) VALUES (?, ?, ?, ?)",
        (token_hash(token), user_id, now, now),
    )
    db.commit()
    return token


def delete_session(token):
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))
    db.commit()


@app.before_request
def load_user():
    g.user = None
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return
    db = get_db()
    row = db.execute(
        "SELECT s.created_at AS s_created, s.last_seen, "
        "u.id, u.username, u.role, u.user_group, u.is_active "
        "FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = ?",
        (token_hash(token),),
    ).fetchone()
    if row is None:
        return
    now = time.time()
    expired = (now - row["last_seen"] > IDLE_TIMEOUT
               or now - row["s_created"] > ABSOLUTE_TIMEOUT)
    if expired or not row["is_active"]:
        delete_session(token)
        return
    db.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?",
               (now, token_hash(token)))
    db.commit()
    g.user = row





@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not username or not email:
            error = "Username and email are required."
        elif password_error(username, password):
            error = password_error(username, password)
        else:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, ph.hash(password)),
                )
                db.commit()
                audit("register_ok", username)
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "Registration failed. Try another username or email."
        audit("register_fail", username)
    return render_template("register.html", error=error)


def login_username():
    return "user:" + request.form.get("username", "").strip().lower()


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
@limiter.limit("10 per hour", key_func=login_username, methods=["POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT id, password_hash, is_active FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        stored = user["password_hash"] if user else DUMMY_HASH
        try:
            ph.verify(stored, password)
            ok = user is not None and user["is_active"] == 1
        except (VerificationError, InvalidHashError):
            ok = False
        if ok:
            if ph.check_needs_rehash(stored):
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                           (ph.hash(password), user["id"]))
                db.commit()
            old_token = request.cookies.get(COOKIE_NAME)
            if old_token:
                delete_session(old_token)
            token = create_session(user["id"])
            audit("login_ok", username)
            resp = redirect(url_for("profile"))
            resp.set_cookie(COOKIE_NAME, token, secure=True, httponly=True,
                            samesite="Lax", path="/")
            return resp
        error = "Invalid username or password."
        audit("login_fail", username)
        return render_template("login.html", error=error), 401
    return render_template("login.html", error=error)


@app.errorhandler(429)
def too_many_requests(e):
    audit("rate_limited", request.form.get("username", ""))
    error = "Too many login attempts. Try again later."
    return render_template("login.html", error=error), 429





@app.route("/logout", methods=["POST"])
def logout():
    token = request.cookies.get(COOKIE_NAME)
    if token:
        delete_session(token)
    audit("logout", g.user["username"] if g.user else "")
    resp = redirect(url_for("login"))
    resp.delete_cookie(COOKIE_NAME, path="/", secure=True, httponly=True,
                       samesite="Lax")
    return resp


@app.route("/profile")
def profile():
    if g.user is None:
        return redirect(url_for("login"))
    return render_template("profile.html", user=g.user)


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def delete_user_sessions(user_id):
    db = get_db()
    db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    db.commit()


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if g.user is None:
        return redirect(url_for("login"))
    error = None
    done = False
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        db = get_db()
        row = db.execute(
            "SELECT username, password_hash FROM users WHERE id = ?",
            (g.user["id"],),
        ).fetchone()
        try:
            ph.verify(row["password_hash"], current)
            current_ok = True
        except (VerificationError, InvalidHashError):
            current_ok = False
        if not current_ok:
            error = "Current password is incorrect."
            audit("change_password_fail", row["username"])
        elif password_error(row["username"], new):
            error = password_error(row["username"], new)
        elif new == current:
            error = "New password must differ from the current one."
        else:
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                       (ph.hash(new), g.user["id"]))
            db.commit()
            delete_user_sessions(g.user["id"])
            audit("change_password_ok", row["username"])
            resp = make_response(render_template("change_password.html", done=True))
            resp.delete_cookie(COOKIE_NAME, path="/", secure=True, httponly=True,
                               samesite="Lax")
            return resp
    return render_template("change_password.html", error=error, done=done)


@app.route("/")
def index():
    if g.user:
        return redirect(url_for("profile"))
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)