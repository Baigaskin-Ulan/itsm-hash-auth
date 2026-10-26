import sqlite3

con = sqlite3.connect("app.db")
with open("schema.sql", encoding="utf-8") as f:
    con.executescript(f.read())
con.close()
print("Database created: app.db")