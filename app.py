from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import secrets, os
from bcrypt import hashpw, gensalt, checkpw
from utils.encryption import encrypt_data, decrypt_data
from datetime import timedelta
from flask_mail import Mail, Message
from functools import wraps
from dotenv import load_dotenv
app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv('SECRET_KEY')  # Use dotenv for production
# Add this block right after app initialization
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')        # Use Gmail App Password

mail = Mail(app)  # ✅ This initializes Flask-Mail
app.permanent_session_lifetime = timedelta(minutes=5) # session log-out
def generate_otp():
    return str(secrets.randbelow(1000000)).zfill(6)

# Database setup
def init_db():
    with sqlite3.connect('database/edusmart.db') as conn:
        c = conn.cursor()

        # Users table
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                email TEXT NOT NULL
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

        # Grades table
        c.execute('''
            CREATE TABLE IF NOT EXISTS grades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student TEXT,
                encrypted_grade BLOB
            )
        ''')

        conn.commit()



init_db()

# Routes
def role_required(required_role):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'username' not in session or session.get('role') != required_role:
                flash('Access denied.', 'danger')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated
    return wrapper

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']  # New field
        role = request.form['role']
        hashed_pw = hashpw(password.encode('utf-8'), gensalt())

        conn = sqlite3.connect('database/edusmart.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                      (username, hashed_pw, role, email))
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email_input = request.form['email']

        conn = sqlite3.connect('database/edusmart.db')
        c = conn.cursor()
        c.execute("SELECT password, role, email FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and checkpw(password.encode('utf-8'), user[0]):
            registered_email = user[2]
            if email_input != registered_email:
                log_attempt(username, "Email mismatch")
                flash('Email does not match our records.', 'danger')
                return redirect(url_for('login'))

            session['username'] = username
            session['email'] = user[2]  # Store email for grade lookup
            session['role'] = user[1]
            session.permanent = True

            otp = generate_otp()
            session['otp'] = otp

            log_attempt(username, "OTP sent")

            msg = Message('Your EduSmart OTP', sender='xyz202511@gmail.com', recipients=[registered_email])
            msg.body = f'Hello {username},\n\nYour OTP is: {otp}\n\nPlease enter it to complete login.'
            mail.send(msg)

            flash('OTP sent to your registered email.', 'info')
            return redirect(url_for('verify_otp'))
        else:
            log_attempt(username, "Invalid credentials")
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')


# Role-Based Dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    role = session.get('role')
    if role == 'student':
        return render_template('student_dashboard.html')
    elif role == 'lecturer':
        return render_template('lecturer_dashboard.html')
    elif role == 'admin':
        return render_template('admin_dashboard.html')
    else:
        flash('Invalid role. Access denied.', 'danger')
        return redirect(url_for('login'))
    

# OTP Verification Route
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session:
        flash('OTP expired or missing. Please log in again.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session['otp']:
            session.pop('otp', None)
            flash('OTP verified. Access granted.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
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

# Route to Store Encrypted Grade
@app.route('/submit_grade', methods=['GET', 'POST'])
@role_required('admin')
def submit_grade():
    if request.method == 'POST':
        name = request.form['student_name']
        email = request.form['student_email']
        subject = request.form['subject']
        grade = request.form['grade']
        encrypted = encrypt_data(grade)

        with sqlite3.connect('database/edusmart.db') as conn:
            c = conn.cursor()
            c.execute("INSERT INTO grades (student_name, student_email, subject, encrypted_grade) VALUES (?, ?, ?, ?)",
                      (name, email, subject, encrypted))
            conn.commit()

        flash('Subject-wise grade stored successfully.', 'success')
    return render_template('submit_grade.html')


# Route to View Decrypted Grades
@app.route('/view_grades')
def view_grades():
    if 'username' not in session or session['role'] != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('database/edusmart.db')
    c = conn.cursor()
    c.execute("SELECT student, encrypted_grade FROM grades")
    rows = c.fetchall()
    conn.close()

    decrypted = []
    for student, encrypted_grade in rows:
        try:
            grade = decrypt_data(encrypted_grade)
        except Exception as e:
            grade = "[Error]"
            print(f"Decryption failed for {student}: {e}")
        decrypted.append((student, grade))

    return render_template('view_grades.html', grades=decrypted)


@app.route('/my_grades')
@role_required('student')
def my_grades():
    email = session.get('email')  # Store email during login

    with sqlite3.connect('database/edusmart.db') as conn:
        c = conn.cursor()
        c.execute("SELECT subject, encrypted_grade FROM grades WHERE student_email = ?", (email,))
        rows = c.fetchall()

    decrypted = []
    for subject, encrypted_grade in rows:
        try:
            grade = decrypt_data(encrypted_grade)
        except Exception:
            grade = "[Error]"
        decrypted.append((subject, grade))

    return render_template('student_grades.html', grades=decrypted)
