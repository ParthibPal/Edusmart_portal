from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import secrets
from bcrypt import hashpw, gensalt, checkpw

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Use dotenv for production

def generate_otp():
    return str(secrets.randbelow(1000000)).zfill(6)

# Database setup
def init_db():
    conn = sqlite3.connect('database/edusmart.db')
    c = conn.cursor()

    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    # Login logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            status TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


init_db()

# Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_pw = hashpw(password.encode('utf-8'), gensalt())

        conn = sqlite3.connect('database/edusmart.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                      (username, hashed_pw, role))
            conn.commit()
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

def log_attempt(username, status):
    conn = sqlite3.connect('database/edusmart.db')
    c = conn.cursor()
    c.execute("INSERT INTO login_logs (username, status) VALUES (?, ?)", (username, status))
    conn.commit()
    conn.close()

# Login + RBAC
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database/edusmart.db')
        c = conn.cursor()
        c.execute("SELECT password, role FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and checkpw(password.encode('utf-8'), user[0]):
            log_attempt(username, 'success')
            otp = generate_otp()
            session['otp'] = otp
            session['username'] = username
            session['role'] = user[1]
            print(f"Your OTP is: {otp}")  # Display in terminal
            return redirect(url_for('verify_otp'))
        else:
            log_attempt(username, 'failure')
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')


# Role-Based Dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    role = session.get('role')
    if role == 'admin':
        return render_template('admin_dashboard.html')
    elif role == 'student':
        return render_template('student_dashboard.html')
    elif role == 'lecturer':
        return render_template('lecturer_dashboard.html')
    else:
        flash('Unknown role.', 'danger')
        return redirect(url_for('login'))
    

# OTP Verification Route
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session['otp']:
            session.pop('otp', None)
            flash('OTP verified. Access granted.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP.', 'danger')
    return render_template('verify_otp.html')


@app.route('/admin/logs')
def view_logs():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('database/edusmart.db')
    c = conn.cursor()
    c.execute("SELECT username, status, timestamp FROM login_logs ORDER BY timestamp DESC")
    logs = c.fetchall()
    conn.close()

    return render_template('admin_logs.html', logs=logs)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))
