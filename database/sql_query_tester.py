import sqlite3

conn = sqlite3.connect('database/edusmart.db')
c = conn.cursor()

with sqlite3.connect('database/edusmart.db') as conn:
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS grades")
    c.execute("""
        CREATE TABLE grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_name TEXT,
            student_email TEXT,
            subject TEXT,
            encrypted_grade BLOB
        )
    """)
    print("Grades table recreated.")



conn.commit()
conn.close()
