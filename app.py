import os
import re
import subprocess
from datetime import datetime

import bcrypt
import mysql.connector
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename
from dotenv import load_dotenv


load_dotenv()

APP_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-only-change-me")

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "security_db")

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "txt"}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB

app = Flask(__name__)
app.config.update(
    SECRET_KEY=APP_SECRET_KEY,
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
)


def get_db_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        autocommit=True,
    )



def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def sanitize_username(username: str) -> str:
    # basic normalization to reduce accidental duplicates
    return username.strip()


@app.errorhandler(413)
def too_large(_e):
    flash("File is too large.", "danger")
    return redirect(url_for("dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = sanitize_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))

        if len(username) > 50:
            flash("Username must be 50 characters or fewer.", "danger")
            return redirect(url_for("register"))

        # bcrypt hashing
        password_bytes = password.encode("utf-8")
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password_bytes, salt).decode("utf-8")

        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            # Check unique username
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cur.fetchone() is not None:
                flash("Username already exists.", "danger")
                return redirect(url_for("register"))

            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, password_hash),
            )

            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
        except mysql.connector.Error as e:
            flash(f"Database error: {e}", "danger")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = sanitize_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("login"))

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT id, username, password_hash FROM users WHERE username = %s", (username,))
        user = cur.fetchone()

        if user is None:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

        stored_hash = user["password_hash"].encode("utf-8")
        if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

        # session management
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]

        return redirect(url_for("dashboard"))

    return render_template("login.html")


def login_required(view_func):
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    wrapper.__name__ = view_func.__name__
    return wrapper


@app.route("/dashboard")
@login_required
def dashboard():
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT file_id, file_name, upload_date FROM uploaded_files WHERE user_id = %s ORDER BY upload_date DESC",
            (session["user_id"],),
        )
        files = cur.fetchall()  # may be []
        return render_template("dashboard.html", files=files)
    except mysql.connector.Error as e:
        flash(f"Dashboard DB error: {e}", "danger")
        return render_template("dashboard.html", files=[]), 200
    except Exception as e:
        flash(f"Dashboard error: {e}", "danger")
        return render_template("dashboard.html", files=[]), 200
    finally:
        try:
            if cur is not None:
                cur.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass




@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        flash("No file part in the request.", "danger")
        return redirect(url_for("dashboard"))

    file = request.files["file"]
    if file.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("dashboard"))

    if not allowed_file(file.filename):
        flash("File type not allowed.", "danger")
        return redirect(url_for("dashboard"))

    original_name = file.filename
    filename = secure_filename(original_name)

    # avoid collisions by prefixing timestamp
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    final_name = f"{timestamp}_{filename}"

    save_path = os.path.join(app.config["UPLOAD_FOLDER"], final_name)
    file.save(save_path)

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "INSERT INTO uploaded_files (user_id, file_name) VALUES (%s, %s)",
            (session["user_id"], original_name),
        )
        flash("File uploaded successfully.", "success")
        return redirect(url_for("dashboard"))
    except mysql.connector.Error as e:
        flash(f"Upload DB error: {e}", "danger")
        return redirect(url_for("dashboard"))
    except Exception as e:
        flash(f"Upload error: {e}", "danger")
        return redirect(url_for("dashboard"))
    finally:
        try:
            if cur is not None:
                cur.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass



@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


def _mock_reconjt(domain: str) -> tuple[str, str, str]:
    # Dummy/sample output during Windows development.
    whois = f"Registrar: Example Registrar\nCreated: 2020\nDomain: {domain}\nStatus: active\n"
    nslookup = f"Server: 8.8.8.8\nAddress: 8.8.8.8\n\nNon-authoritative answer:\n{domain}\tname = {domain}.\nIP Address: 142.0.0.1\n"
    dig = f"; <<>> DiG 9.18.1\n;; QUESTION SECTION:\n;{domain}.\n\n;; ANSWER SECTION:\n{domain}.\t3600\tIN\tMX\t10 mail.{domain}.\n\n;; ADDITIONAL SECTION:\nmail.{domain}.\t3600\tIN\tA\t142.0.0.1\n"
    return whois, nslookup, dig


def run_reconjt(domain: str) -> tuple[str, str, str]:
    """Runs ./reconjt.sh <domain> and returns (whois, nslookup, dig).

    On Windows or if reconjt.sh is missing, returns mock output.
    """
    script_path = os.path.join(os.path.dirname(__file__), "reconjt.sh")

    # Detect Windows early (most local dev).
    if os.name == "nt" or not os.path.exists(script_path):
        return _mock_reconjt(domain)

    # Script exists; run it.
    try:
        completed = subprocess.run(
            [script_path, domain],
            capture_output=True,
            text=True,
            check=False,
        )

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        combined = stdout + ("\n" + stderr if stderr.strip() else "")

        # Attempt to split into sections if script uses markers.
        # Expected markers: WHOIS / NSLOOKUP / DIG (case-insensitive).
        def extract(marker: str) -> str:
            import re

            pattern = rf"{marker}\s*:?.*"  # marker line
            # Find marker index
            m = re.search(pattern, combined, flags=re.IGNORECASE)
            if not m:
                return ""
            start = m.end()
            # next marker
            next_markers = ["WHOIS", "NSLOOKUP", "DIG"]
            next_pattern = rf"(?:{'|'.join(next_markers)})\s*:"
            m2 = re.search(next_pattern, combined[m.end():], flags=re.IGNORECASE)
            if not m2:
                return combined[start:].strip()
            return combined[start : m.end() + m2.start()].strip()

        whois = extract("WHOIS")
        nslookup = extract("NSLOOKUP")
        dig = extract("DIG")

        # If splitting failed, fallback to naive grouping.
        if not (whois or nslookup or dig):
            whois = combined.strip()
            nslookup = ""
            dig = ""

        return whois, nslookup, dig
    except Exception:
        return _mock_reconjt(domain)


@app.route("/recon", methods=["GET"])
@login_required
def recon_home():
    return render_template("recon_home.html")




@app.route("/recon/scan", methods=["POST"])
@login_required
def recon_scan():

    domain = (request.form.get("domain") or "").strip()
    if not domain:
        flash("Domain is required.", "danger")
        return redirect(url_for("recon_home"))

    if len(domain) > 253:
        flash("Domain is too long.", "danger")
        return redirect(url_for("recon_home"))

    try:
        whois, nslookup, dig = run_reconjt(domain)
        request_ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        return render_template(
            "recon_results.html",
            domain=domain,
            request_ts=request_ts,
            whois=whois or "(no output)",
            nslookup=nslookup or "(no output)",
            dig=dig or "(no output)",
        )
    except Exception as e:
        return render_template("error.html", message=f"Scan failed: {e}"), 500


@app.route("/recon/about", methods=["GET"])
def recon_about():
    return render_template("about.html")


@app.route("/recon/error", methods=["GET"])
def recon_error():
    return render_template("error.html", message="Unexpected error."), 500


if __name__ == "__main__": 
    app.run(debug=True, host="0.0.0.0", port=5000)


