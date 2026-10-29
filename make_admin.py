"""Grant the admin role to a user. Usage: python make_admin.py <username>"""
import sqlite3
import sys

if len(sys.argv) != 2:
    sys.exit("Usage: python make_admin.py <username>")
con = sqlite3.connect("app.db")
n = con.execute("UPDATE users SET role = 'admin' WHERE username = ?", (sys.argv[1],)).rowcount
con.commit()
con.close()
print(f"{n} user(s) updated. '{sys.argv[1]}' is now admin." if n else f"No user named '{sys.argv[1]}'.")
