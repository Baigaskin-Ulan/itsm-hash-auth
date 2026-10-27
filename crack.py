"""
crack.py - demonstration for the report (ITSM PL2, topic: Hash + salt).

Shows why fast, unsalted hashing is dangerous and why Argon2id with a salt is not.
It builds a small SET OF TEST ACCOUNTS (invented passwords only), stores them two
ways, and runs a dictionary of common passwords against both. Everything is local;
nothing here touches the real application database or the network.

Run:  python crack.py
"""
import hashlib
import sqlite3
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

# Test accounts for the demo. Three weak passwords that appear in the blocklist,
# one long random password that does not. These are invented, not anyone's.
TEST_USERS = {
    "demo_weak1": "123456789123456",
    "demo_weak2": "qwertyuiopasdfg",
    "demo_weak3": "123456789123456",       # same as demo_weak1 on purpose
    "demo_strong": "Z9!mK2$pX7&qL4@wR8",
}

DB = "crack_demo.db"


def build_demo_db():
    """Store each test password two ways: SHA-256 (no salt) and Argon2id (salted)."""
    con = sqlite3.connect(DB)
    con.execute("DROP TABLE IF EXISTS demo")
    con.execute("CREATE TABLE demo (username TEXT, sha256 TEXT, argon2 TEXT)")
    for user, pw in TEST_USERS.items():
        sha = hashlib.sha256(pw.encode()).hexdigest()
        con.execute("INSERT INTO demo VALUES (?, ?, ?)", (user, sha, ph.hash(pw)))
    con.commit()
    con.close()


def load_dictionary():
    """The attacker's wordlist = the project's own common-password blocklist."""
    with open("blocklist.txt", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def show_equal_hashes():
    con = sqlite3.connect(DB)
    rows = con.execute("SELECT username, sha256, argon2 FROM demo").fetchall()
    con.close()
    print("Same password, two storage schemes:")
    for user, sha, arg in rows:
        print(f"  {user:12} sha256={sha[:16]}...  argon2={arg[:32]}...")
    print("  -> demo_weak1 and demo_weak3 share a password:")
    print("     SHA-256 hashes are IDENTICAL (no salt); Argon2id hashes DIFFER (per-user salt).\n")


def crack_sha256(dictionary):
    con = sqlite3.connect(DB)
    targets = dict(con.execute("SELECT sha256, username FROM demo").fetchall())
    con.close()
    found, checks, start = {}, 0, time.perf_counter()
    for word in dictionary:
        checks += 1
        h = hashlib.sha256(word.encode()).hexdigest()
        if h in targets:
            found[targets[h]] = word
    elapsed = time.perf_counter() - start
    rate = checks / elapsed if elapsed else 0
    print(f"SHA-256 (no salt): {checks} words in {elapsed:.3f} s = {rate:,.0f} guesses/s")
    for user, pw in found.items():
        print(f"  CRACKED {user}: {pw}")
    if not found:
        print("  nothing cracked")
    return rate, found


def crack_argon2(dictionary, limit=100):
    """Argon2id has no lookup table: each guess must be verified against each user."""
    con = sqlite3.connect(DB)
    rows = con.execute("SELECT username, argon2 FROM demo").fetchall()
    con.close()
    found, checks, start = {}, 0, time.perf_counter()
    for word in dictionary[:limit]:
        for user, stored in rows:
            checks += 1
            try:
                ph.verify(stored, word)
                found[user] = word
            except VerifyMismatchError:
                pass
    elapsed = time.perf_counter() - start
    rate = checks / elapsed if elapsed else 0
    print(f"Argon2id (salted): {checks} verifications in {elapsed:.3f} s = {rate:,.1f} guesses/s")
    for user, pw in found.items():
        print(f"  CRACKED {user}: {pw}")
    if not found:
        print("  nothing cracked (in the sampled words)")
    return rate, found


def main():
    build_demo_db()
    dictionary = load_dictionary()
    print(f"Dictionary: {len(dictionary)} common passwords (blocklist.txt)\n")
    show_equal_hashes()
    sha_rate, _ = crack_sha256(dictionary)
    print()
    arg_rate, _ = crack_argon2(dictionary, limit=100)
    print()
    if arg_rate:
        print(f"SHA-256 is about {sha_rate / arg_rate:,.0f}x faster to attack than Argon2id.")
    print("Lesson: a salt removes duplicates and precomputed tables; a slow, memory-hard")
    print("function makes a dictionary attack impractical. Strong passwords survive both.")


if __name__ == "__main__":
    main()
