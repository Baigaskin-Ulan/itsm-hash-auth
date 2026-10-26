import hashlib
import secrets
import sqlite3
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import Flask, g, redirect, render_template, request, url_for
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)
csrf = CSRFProtect(app)

ph = PasswordHasher()
DUMMY_HASH = ph.hash("dummy-password-for-timing")

DB_PATH = "app.db"
COOKIE_NAME = "__Host-sid"
IDLE_TIMEOUT = 30 * 60
ABSOLUTE_TIMEOUT = 8 * 60 * 60
MIN_LEN = 15
MAX_LEN = 128




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
        elif not MIN_LEN <= len(password) <= MAX_LEN:
            error = f"Password must be {MIN_LEN} to {MAX_LEN} characters long."
        else:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, ph.hash(password)),
                )
                db.commit()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "Registration failed. Try another username or email."
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
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
            resp = redirect(url_for("profile"))
            resp.set_cookie(COOKIE_NAME, token, secure=True, httponly=True,
                            samesite="Lax", path="/")
            return resp
        error = "Invalid username or password."
    return render_template("login.html", error=error)





@app.route("/logout", methods=["POST"])
def logout():
    token = request.cookies.get(COOKIE_NAME)
    if token:
        delete_session(token)
    resp = redirect(url_for("login"))
    resp.delete_cookie(COOKIE_NAME, path="/", secure=True, httponly=True,
                       samesite="Lax")
    return resp


@app.route("/profile")
def profile():
    if g.user is None:
        return redirect(url_for("login"))
    return render_template("profile.html", user=g.user)


@app.route("/")
def index():
    if g.user:
        return redirect(url_for("profile"))
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)