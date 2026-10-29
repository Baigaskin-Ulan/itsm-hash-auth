# ITSM Practical Work No. 2 — Web Authentication Security

Topic: **Hash (password + salt) — Argon2id**
Course: Information Technology Security Methods (ITSM), VILNIUS TECH, 2026–2027.
Author: Ulan Baigaskin, group ITSfmu-26.

A small Flask application whose login is secured with salted, slow password
hashing (Argon2id). A leaked database reveals no passwords, and equal passwords
give different records.

## Features

Base mechanism:
- Argon2id password hashing with a per-user salt (`argon2-cffi`).
- Generic login error plus a dummy hash, so timing does not reveal which
  usernames exist.
- Server-side sessions: a random token in the `__Host-sid` cookie
  (`Secure`, `HttpOnly`, `SameSite=Lax`); only its SHA-256 is stored.
- Session rotation at login; idle (30 min) and absolute (8 h) timeouts;
  server-side logout.
- Rate limiting (5/min per IP, 10/hour per username).
- Common-password blocklist (10,908 entries) and a username-in-password check.
- CSRF protection on every form; security response headers; a 16 KB request cap.
- Authentication logging to `auth.log` (no secrets).

Full solution:
- One-time backup codes (stored as Argon2id hashes).
- Password reset by a single-use, 30-minute token (no user enumeration).
- Admin panel: revoke sessions, force reset, disable/enable — by user or group;
  re-authentication required; actions written to `audit_actions`.

## Requirements

- Python 3.12 or newer
- The packages in `requirements.txt` (Flask, argon2-cffi, Flask-Limiter, Flask-WTF)

## Setup and run (Windows PowerShell)

    git clone https://github.com/Baigaskin-Ulan/itsm-hash-auth.git
    cd itsm-hash-auth
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    python make_blocklist.py        # downloads and builds blocklist.txt
    python init_db.py               # creates app.db from schema.sql
    python app.py                   # serves http://localhost:5000

On macOS or Linux, activate the environment with
`source .venv/bin/activate` instead.

## Making an administrator

The admin role is set once, directly in the database, after registering a user:

    python make_admin.py <username>

The admin panel is then available at `/admin`.

## Demonstrations

- `python crack.py` — a dictionary attack against test accounts, comparing
  unsalted SHA-256 with Argon2id, to show why salt and slow hashing matter.

## Project layout

| Path | Purpose |
| --- | --- |
| `app.py` | routes, Argon2id, sessions, rate limiting, CSRF, admin panel |
| `schema.sql`, `init_db.py` | database schema and its creation |
| `make_blocklist.py`, `blocklist.txt` | common-password blocklist |
| `crack.py` | salt vs slow-hashing demonstration |
| `make_admin.py` | grant the admin role |
| `templates/` | HTML pages |

## Notes

- There is no mail server; password-reset links are printed to the server console.
- `app.db`, `.venv/`, `auth.log` and secrets are excluded from Git (`.gitignore`).
- HTTPS is assumed in production; the app runs on `http://localhost` for the lab.
