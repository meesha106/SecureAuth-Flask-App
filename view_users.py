import sqlite3

DB_FILE = 'users.db'
conn = sqlite3.connect(DB_FILE)
c = conn.cursor()

# View all data in users table
c.execute("SELECT * FROM users;")
rows = c.fetchall()

if rows:
    for row in rows:
        print(row)
else:
    print("No data in users table yet.")

conn.close()