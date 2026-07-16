# Secure User Management and File Upload System (Flask + MySQL)

## Features
- User registration (unique username) with bcrypt-hashed passwords
- User login with secure session management
- Protected dashboard with file upload
- Upload constraints: size limit, allowed extensions
- File metadata stored in MySQL (`uploaded_files`)

## Prerequisites
- Python 3.10+
- MySQL Server

## Setup
1. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure environment variables (example):
   - `FLASK_SECRET_KEY`
   - `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`

## Initialize Database
- Run `database/schema.sql` in your MySQL instance.

## Run
```bash
python app.py
```

Open: http://127.0.0.1:5000/

