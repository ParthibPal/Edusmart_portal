# edusmart_portal
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


<img width="255" height="779" alt="image" src="https://github.com/user-attachments/assets/dafeb452-0322-4712-be67-621d619414c0" />



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
