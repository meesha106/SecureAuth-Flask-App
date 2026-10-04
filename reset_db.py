import sqlite3
import os

DB_FILE = "users.db"

# Delete old database if exists
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)
    print("🗑️ Old database deleted successfully.")

# Create a fresh DB with full schema
conn = sqlite3.connect(DB_FILE)
c = conn.cursor()

c.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash BLOB NOT NULL,
    totp_secret TEXT,
    recovery_codes TEXT,
    email TEXT,
    email_otp TEXT,
    email_otp_expires INTEGER,
    failed_attempts INTEGER DEFAULT 0,
    lockout_until INTEGER
);
""")

conn.commit()
conn.close()
print("✅ New database created successfully with correct schema!")
