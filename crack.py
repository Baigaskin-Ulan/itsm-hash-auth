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

# One hasher with default parameters (m=64 MiB, t=3, p=4). ph.hash() generates a
# fresh random salt every call and embeds the variant, version, parameters and salt
# inside the returned string - so no separate salt column is ever needed.
ph = PasswordHasher()

# Test accounts for the demo. Three weak passwords that appear in the blocklist,
# one long random password that does not. These are invented, not anyone's.
# Note: demo_weak1 and demo_weak3 share a password on purpose, to expose what an
# unsalted hash leaks (identical passwords -> identical SHA-256 hashes).
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
        # Left column: SHA-256, fast and UNSALTED - the wrong way to store a password.
        sha = hashlib.sha256(pw.encode()).hexdigest()
        # Right column: Argon2id, slow, memory-hard and SALTED - the right way.
        con.execute("INSERT INTO demo VALUES (?, ?, ?)", (user, sha, ph.hash(pw)))
    con.commit()
    con.close()


def load_dictionary():
    """The attacker's wordlist = the project's own common-password blocklist."""
    # Reusing blocklist.txt makes the point: these are exactly the passwords the app
    # refuses at registration, and exactly what an attacker tries first after a leak.
    with open("blocklist.txt", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def show_equal_hashes():
    """Prove the salt effect before any cracking: same password, two schemes."""
    con = sqlite3.connect(DB)
    rows = con.execute("SELECT username, sha256, argon2 FROM demo").fetchall()
    con.close()
    print("Same password, two storage schemes:")
    for user, sha, arg in rows:
        print(f"  {user:12} sha256={sha[:16]}...  argon2={arg[:32]}...")
    # demo_weak1 and demo_weak3 have the same password. Without a salt their SHA-256
    # hashes match exactly, so an attacker sees who reuses passwords and can attack
    # them all at once. With Argon2id the per-user salt makes the hashes differ.
    print("  -> demo_weak1 and demo_weak3 share a password:")
    print("     SHA-256 hashes are IDENTICAL (no salt); Argon2id hashes DIFFER (per-user salt).\n")


def crack_sha256(dictionary):
    """Attack the unsalted SHA-256 column.

    Because there is no salt, one hash of a guess can be compared against EVERY
    stored hash at once (a dictionary lookup). This is also why precomputed
    'rainbow tables' work on unsalted hashes. SHA-256 is built to be fast, so this
    runs at hundreds of thousands of guesses per second.
    """
    con = sqlite3.connect(DB)
    # Build one lookup table {hash: username} - all targets checked in a single pass.
    targets = dict(con.execute("SELECT sha256, username FROM demo").fetchall())
    con.close()
    found, checks, start = {}, 0, time.perf_counter()
    for word in dictionary:
        checks += 1
        h = hashlib.sha256(word.encode()).hexdigest()   # hash the guess ONCE...
        if h in targets:                                 # ...compare against ALL users
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
    """Attack the salted Argon2id column.

    There is NO shared lookup here: each stored hash carries its own unique salt, so
    a guess must be verified separately against EVERY user (ph.verify re-reads that
    user's salt and parameters). Each verification is deliberately slow and memory-hard
    (64 MiB), so this runs at only a handful of guesses per second - which is exactly
    the defence. 'limit' caps the sample so the demo finishes in seconds instead of
    grinding through the whole wordlist.
    """
    con = sqlite3.connect(DB)
    rows = con.execute("SELECT username, argon2 FROM demo").fetchall()
    con.close()
    found, checks, start = {}, 0, time.perf_counter()
    for word in dictionary[:limit]:
        for user, stored in rows:          # must try every user separately (unique salt)
            checks += 1
            try:
                ph.verify(stored, word)    # slow + memory-hard: this is the cost
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
    # 1. Store the test passwords both ways.
    build_demo_db()
    dictionary = load_dictionary()
    print(f"Dictionary: {len(dictionary)} common passwords (blocklist.txt)\n")
    # 2. Show the salt effect (identical vs different hashes for the same password).
    show_equal_hashes()
    # 3. Attack the fast, unsalted scheme - weak passwords fall almost instantly.
    sha_rate, _ = crack_sha256(dictionary)
    print()
    # 4. Attack the slow, salted scheme - the same wordlist barely moves.
    arg_rate, _ = crack_argon2(dictionary, limit=100)
    print()
    # 5. Put a number on the gap (typically tens of thousands of times faster).
    if arg_rate:
        print(f"SHA-256 is about {sha_rate / arg_rate:,.0f}x faster to attack than Argon2id.")


if __name__ == "__main__":
    main()
