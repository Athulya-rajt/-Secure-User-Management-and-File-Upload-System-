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


## Preview
'''
<img width="1046" height="305" alt="image" src="https://github.com/user-attachments/assets/4c42b350-4922-4065-a5b0-2016dd8e3f71" />
<img width="1348" height="657" alt="image" src="https://github.com/user-attachments/assets/0285e862-8df9-4956-b948-2cff750c52af" />
<img width="1270" height="708" alt="image" src="https://github.com/user-attachments/assets/280ca0b4-ed64-481f-936a-1810653218ad" />
<img width="1340" height="666" alt="image" src="https://github.com/user-attachments/assets/4f3dad4a-4bed-482c-ad1a-621f9219b64b" />

'''
