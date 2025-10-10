import sqlite3

conn = sqlite3.connect('database/edusmart.db')
c = conn.cursor()

try:
    c.execute("ALTER TABLE users ADD COLUMN email TEXT")
    print("Email column added successfully.")
except sqlite3.OperationalError as e:
    print("Column may already exist or failed:", e)

conn.commit()
conn.close()
