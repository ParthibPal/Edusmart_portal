# Edusmart_portal
# 🎓 EduSmart Portal

EduSmart is a secure, role-based web application designed for academic institutions to manage grades, tuition payments, and learning resources. Built with modern full-stack technologies, it supports Admin, Lecturer, and Student roles with encrypted data handling and intuitive dashboards.

---

## 🚀 Features

- 🔐 **Role-Based Dashboards**  
  Separate interfaces for Admins, Lecturers, and Students with session-aware navigation.

- 🧮 **Encrypted Grade Management**
  Admins can submit subject-wise grades using Fernet encryption; students view decrypted marks securely.

- 🧾 **Tuition Tracking**  
  Admins record payments; students view history with receipt IDs and timestamps.

- 📚 **Learning Resource Uploads**  
  Admins and Lecturers can share links and descriptions; students access curated materials.

- 📩 **OTP-Based Login Security**  
  Email verification with one-time passwords ensures secure access.

- 📊 **Login Logs & Audit Trails**  
  Admins can monitor login attempts and status for accountability.

---

## 🛠️ Tech Stack

| Layer        | Technology                     |
|--------------|--------------------------------|
| Frontend     | HTML, CSS, Jinja2 Templates    |
| Backend      | Python, Flask                  |
| Database     | SQLite                         |
| Security     | bcrypt, Fernet (symmetric encryption) |
| Email        | Flask-Mail (OTP delivery)      |
| Deployment   | Localhost / Cloud-ready        |

---

## 📂 Folder Structure
```
EDUSMART_PORTAL/
│
├── __pycache__/
│   ├── app.cpython-311.pyc
│   ├── app.cpython-313.pyc
│   └── app.cpython-313.pyc
│
├── database/
│   ├── edusmart.db
│   └── sql_query_tester.py
│
├── static/
│   └── style.css
│
├── templates/
│   ├── admin_dashboard.html
│   ├── admin_logs.html
│   ├── base.html
│   ├── dashboard.html
│   ├── home.html
│   ├── lecturer_dashboard.html
│   ├── login.html
│   ├── register.html
│   ├── student_dashboard.html
│   ├── student_grades.html
│   ├── student_tuition.html
│   ├── submit_grade.html
│   ├── submit_tuition.html
│   ├── upload_resource.html
│   ├── verify_otp.html
│   ├── view_grades.html
│   └── view_resources.html
│
├── utils/
│   ├── __pycache__/
│   ├── encryption.py
│   ├── logger.py
│   └── otp.py
│
├── venv/
│
├── .env
├── .gitignore
├── app.py
├── config.py
├── forms.py
├── models.py
├── README.md
├── requirements.txt
└── secret.key
```

---

## 🧑‍💻 Roles & Access

| Role      | Permissions |
|-----------|-------------|
| Admin     | Full access: grades, tuition, logs, resources |
| Lecturer  | Upload resources only |
| Student   | View grades, tuition, and resources |

---

## 🔐 Security Highlights

- Passwords hashed with `bcrypt`
- Grades encrypted with `Fernet` symmetric key
- OTP verification via email
- Session-based role validation

---

## 📈 Future Enhancements

- 📊 Dashboard analytics (student count, tuition summaries)
- 📥 CSV export for grades and payments
- 📱 Mobile-responsive UI
- 🔔 Notification system for new resources or payments
- 🧑‍🏫 Lecturer grade entry support

---

## 📌 Setup Instructions

1. Clone the repo  
   `git clone https://github.com/yourusername/edusmart_portal.git`

2. Create virtual environment  
   `python -m venv venv && source venv/bin/activate`

3. Install dependencies  
   `pip install -r requirements.txt`

4. Generate `secret.key` for encryption  
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key())"`

5. Run the app  
   `python app.py`

---

## 📬 Contact

Built by **Parthib** — aspiring SDE focused on secure, scalable web applications.  
📧 Email: palparthib97@gmail.com  

---
