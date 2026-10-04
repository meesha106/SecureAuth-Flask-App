#.\venv\Scripts\Activate
#http://127.0.0.1:5000

import os
import json
import time
import secrets
import logging
import base64
import sqlite3
from io import BytesIO
from datetime import timedelta

import bcrypt
import pyotp
import qrcode
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, make_response, jsonify
)
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, unset_jwt_cookies,
    set_access_cookies, set_refresh_cookies
)

# ---------------- LOAD ENVIRONMENT ----------------
load_dotenv()  # reads variables from the .env file (never commit that file)


def require_env(name):
    """Return an environment variable or stop the app with a clear error."""
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable: {name}. "
            f"Copy .env.example to .env and fill it in."
        )
    return value


app = Flask(__name__)
app.secret_key = require_env('FLASK_SECRET')
DB_FILE = 'users.db'
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'MEESHA123')

# Set COOKIE_SECURE=true in production (HTTPS only). Leave false for local http.
COOKIE_SECURE = os.environ.get('COOKIE_SECURE', 'false').lower() == 'true'

# ---------------- SESSION COOKIE SETTINGS ----------------
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = COOKIE_SECURE

# ---------------- JWT CONFIGURATION ----------------
app.config['JWT_SECRET_KEY'] = require_env('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=30)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(minutes=2)
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'
app.config['JWT_COOKIE_SECURE'] = COOKIE_SECURE
jwt = JWTManager(app)

# ---------------- MAIL CONFIG ----------------
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = require_env('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = require_env('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER') or os.environ['MAIL_USERNAME']
mail = Mail(app)

# ---------------- RATE LIMITER ----------------
limiter = Limiter(key_func=get_remote_address, default_limits=[])
limiter.init_app(app)

# ---------------- LOGGING ----------------
app_logger = logging.getLogger('secureauth')
app_logger.setLevel(logging.INFO)
fh = logging.FileHandler('login_attempts.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
fh.setFormatter(formatter)
app_logger.addHandler(fh)
logging.getLogger('werkzeug').disabled = True

# ---------------- SECURITY SETTINGS ----------------
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60
EMAIL_OTP_VALIDITY = 5
OTP_COOLDOWN_SECONDS = 60


# ---------------- DATABASE FUNCTIONS ----------------
def create_db_if_not_exists():
    conn = sqlite3.connect(DB_FILE, timeout=10, check_same_thread=False)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
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
    );''')
    conn.commit()
    conn.close()


def generate_recovery_codes(n=5):
    """Generate n one-time recovery codes"""
    return [secrets.token_hex(4) for _ in range(n)]


def get_user(username):
    conn = sqlite3.connect(DB_FILE, timeout=10, check_same_thread=False)
    c = conn.cursor()
    c.execute("""SELECT id, username, password_hash, totp_secret, recovery_codes,
                 email, email_otp, email_otp_expires, failed_attempts, lockout_until
                 FROM users WHERE username = ?""", (username,))
    row = c.fetchone()
    conn.close()
    return row


def add_user(username, password_hash, totp_secret):
    conn = sqlite3.connect(DB_FILE, timeout=10, check_same_thread=False)
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
              (username, password_hash, totp_secret))
    conn.commit()
    conn.close()


def generate_email_otp():
    # secrets is cryptographically secure (random is not)
    return '{:06d}'.format(secrets.randbelow(1000000))


def send_email_otp(to_email, otp):
    msg = Message(subject="Your SecureAuth Login OTP",
                  recipients=[to_email])
    msg.body = f"Your One-Time Login Code is: {otp}\nValid for {EMAIL_OTP_VALIDITY} minutes."
    mail.send(msg)
    app_logger.info(f"Email OTP sent to {to_email}")


def set_email_otp_for_user(username, otp, validity_minutes=EMAIL_OTP_VALIDITY):
    expires = int(time.time() + validity_minutes * 60)
    conn = sqlite3.connect(DB_FILE, timeout=10, check_same_thread=False)
    c = conn.cursor()
    c.execute("UPDATE users SET email_otp=?, email_otp_expires=? WHERE username=?", (otp, expires, username))
    conn.commit()
    conn.close()


def clear_email_otp(username):
    conn = sqlite3.connect(DB_FILE, timeout=10, check_same_thread=False)
    c = conn.cursor()
    c.execute("UPDATE users SET email_otp=NULL, email_otp_expires=NULL WHERE username=?", (username,))
    conn.commit()
    conn.close()


def increment_failed_attempts(username):
    conn = sqlite3.connect(DB_FILE, timeout=10, check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT failed_attempts FROM users WHERE username=?", (username,))
    row = c.fetchone()
    if row:
        failed = (row[0] or 0) + 1
        lock_until = None
        if failed >= MAX_FAILED_ATTEMPTS:
            lock_until = int(time.time() + LOCKOUT_SECONDS)
            app_logger.warning(f"Account locked for {username} after {failed} failed attempts")
        c.execute("UPDATE users SET failed_attempts=?, lockout_until=? WHERE username=?", (failed, lock_until, username))
        conn.commit()
    conn.close()


def reset_failed_attempts(username):
    conn = sqlite3.connect(DB_FILE, timeout=10, check_same_thread=False)
    c = conn.cursor()
    c.execute("UPDATE users SET failed_attempts=0, lockout_until=NULL WHERE username=?", (username,))
    conn.commit()
    conn.close()


def is_account_locked(user_row):
    if not user_row:
        return False, None
    lockout_until = user_row[9]
    if lockout_until and time.time() < int(lockout_until):
        return True, int(lockout_until)
    return False, None


def login_success_response(username):
    """Issue JWT cookies and redirect to the dashboard."""
    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)
    response = make_response(redirect(url_for('dashboard')))
    set_access_cookies(response, access_token)
    set_refresh_cookies(response, refresh_token)
    session.pop('temp_user', None)
    return response


# ---------------- ROUTES ----------------
@app.route('/')
def home():
    return render_template('home.html')


# -------- REGISTER --------
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        email = request.form.get('email', '')

        # --- Check if user exists ---
        if get_user(username):
            return render_template('register.html', message="Username already exists", error=True)

        # --- Hash password ---
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        # --- Generate TOTP secret ---
        secret = pyotp.random_base32()

        # --- Generate Recovery Codes ---
        recovery_codes = generate_recovery_codes(5)

        # --- Add user to DB ---
        add_user(username, hashed, secret)

        # --- Add email if provided ---
        conn = sqlite3.connect(DB_FILE, timeout=10, check_same_thread=False)
        c = conn.cursor()
        c.execute("UPDATE users SET email=?, recovery_codes=? WHERE username=?",
                  (email, json.dumps(recovery_codes), username))
        conn.commit()
        conn.close()

        # --- Generate TOTP URL + QR Code ---
        totp_url = f"otpauth://totp/SecureAuth:{username}?secret={secret}&issuer=SecureAuth"
        img = qrcode.make(totp_url)
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()

        app_logger.info(f"New user registered: {username}")

        # --- Show success page with codes + QR ---
        return render_template(
            'registered.html',
            username=username,
            secret=secret,
            qr_code=qr_base64,
            recovery_codes=recovery_codes
        )

    return render_template('register.html')


# -------- LOGIN --------
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = get_user(username)
        locked, unlock_ts = is_account_locked(user)
        if locked:
            unlock_in = int(unlock_ts - time.time())
            return render_template('login.html', message=f"Account locked. Try again in {unlock_in//60}m {unlock_in%60}s", error=True)
        if user and bcrypt.checkpw(password.encode(), user[2]):
            reset_failed_attempts(username)
            session['temp_user'] = username
            return redirect(url_for('verify'))
        increment_failed_attempts(username)
        app_logger.info(f"Failed password attempt for {username}")
        return render_template('login.html', message="Invalid credentials", error=True)
    return render_template('login.html')


# -------- VERIFY (2FA) --------
@app.route('/verify', methods=['GET', 'POST'])
@limiter.limit("8 per minute")
def verify():
    username = session.get('temp_user')
    if not username:
        return redirect(url_for('login'))

    user = get_user(username)
    if not user:
        return redirect(url_for('login'))

    locked, unlock_ts = is_account_locked(user)
    if locked:
        unlock_in = int(unlock_ts - time.time())
        return render_template('verify.html', message=f"Locked. Try again in {unlock_in//60}m {unlock_in%60}s", error=True)

    # --- HANDLE "SEND EMAIL OTP" BUTTON ---
    if request.method == 'POST' and 'send_email' in request.form:
        if not user[5]:
            return render_template('verify.html', message="No email configured for this user.", error=True)

        otp = generate_email_otp()
        set_email_otp_for_user(username, otp)
        try:
            send_email_otp(user[5], otp)
            app_logger.info(f"Email OTP sent successfully to {user[5]}")
            return render_template('verify.html', message="✅ Email OTP sent. Check your inbox.", error=False)
        except Exception as e:
            # Log the details, but don't expose SMTP errors to the browser
            app_logger.error(f"Email OTP sending failed: {e}")
            return render_template('verify.html', message="Failed to send Email OTP. Please try again later.", error=True)

    # --- VERIFY OTP or Recovery Code ---
    if request.method == 'POST':
        code = request.form.get('totp', '').strip()
        totp = pyotp.TOTP(user[3] or '')

        # --- 1️⃣ Authenticator App (TOTP) ---
        if user[3] and totp.verify(code, valid_window=1):
            reset_failed_attempts(username)
            app_logger.info(f"TOTP success for {username}")
            return login_success_response(username)

        # --- 2️⃣ Email OTP ---
        email_otp, expires = user[6], user[7]
        if email_otp and code == email_otp and time.time() < int(expires):
            clear_email_otp(username)
            reset_failed_attempts(username)
            app_logger.info(f"Email OTP success for {username}")
            return login_success_response(username)

        # --- 3️⃣ Recovery Code ---
        try:
            recovery_codes = json.loads(user[4]) if user[4] else []
        except Exception:
            recovery_codes = []
        if code in recovery_codes:
            recovery_codes.remove(code)
            conn = sqlite3.connect(DB_FILE, timeout=10, check_same_thread=False)
            c = conn.cursor()
            c.execute("UPDATE users SET recovery_codes=? WHERE username=?", (json.dumps(recovery_codes), username))
            conn.commit()
            conn.close()

            reset_failed_attempts(username)
            app_logger.info(f"✅ Recovery code used for {username}")
            return login_success_response(username)

        # --- If nothing matched ---
        increment_failed_attempts(username)
        return render_template('verify.html', message="Invalid or expired OTP.", error=True)

    return render_template('verify.html')


# -------- DASHBOARD (ADMIN/USER SPLIT) --------
@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    if current_user == ADMIN_USERNAME:
        return redirect(url_for('admin'))
    return render_template('user_home.html', user=current_user)


# -------- ADMIN PANEL --------
@app.route('/admin')
@jwt_required()
def admin():
    current_user = get_jwt_identity()
    if current_user != ADMIN_USERNAME:
        return redirect(url_for('login'))

    conn = sqlite3.connect(DB_FILE, timeout=10, check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT username, email, failed_attempts, lockout_until FROM users")
    rows = c.fetchall()
    conn.close()

    users = [
        {
            'username': r[0],
            'email': r[1],
            'failed_attempts': r[2],
            'lockout_until': r[3]
        } for r in rows
    ]

    logs = []
    if os.path.exists('login_attempts.log'):
        # Use UTF-8 and skip unreadable characters
        with open('login_attempts.log', 'r', encoding='utf-8', errors='ignore') as f:
            logs = [
                line.strip() for line in f.readlines()[-50:]
                if any(kw in line.lower() for kw in ["success", "locked", "failed"])
            ]

    return render_template('admin.html', users=users, now=int(time.time()), logs=logs)


# -------- LOCK / UNLOCK USER --------
@app.route('/lock_user/<username>', methods=['POST'])
@jwt_required(optional=True)
def lock_user(username):
    current_user = get_jwt_identity()
    if not current_user:
        return jsonify({"msg": "Token expired"}), 401
    if current_user != ADMIN_USERNAME:
        return redirect(url_for('login'))

    conn = None
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10, check_same_thread=False)
        c = conn.cursor()

        c.execute("SELECT lockout_until FROM users WHERE username=?", (username,))
        result = c.fetchone()
        now_ts = int(time.time())

        if not result:
            return redirect(url_for('admin'))

        current_lock = result[0]
        if current_lock and current_lock > now_ts:
            c.execute("UPDATE users SET lockout_until=NULL, failed_attempts=0 WHERE username=?", (username,))
            app_logger.info(f"✅ Admin unlocked user {username}")
        else:
            c.execute("UPDATE users SET lockout_until=? WHERE username=?", (now_ts + LOCKOUT_SECONDS, username))
            app_logger.warning(f"🔒 Admin locked user {username} manually")

        conn.commit()
    except sqlite3.OperationalError as e:
        app_logger.error(f"Database locked while updating {username}: {e}")
        time.sleep(1)  # slight delay before retry
        return jsonify({"error": "Database busy, try again"}), 503
    finally:
        if conn:
            conn.close()

    return redirect(url_for('admin'))


# -------- ADMIN STATS (for Chart.js) --------
@app.route('/admin_stats')
@jwt_required()
def admin_stats():
    try:
        current_user = get_jwt_identity()
        if current_user != ADMIN_USERNAME:
            return jsonify({"error": "Unauthorized"}), 403

        conn = sqlite3.connect(DB_FILE, timeout=10, check_same_thread=False)
        c = conn.cursor()
        c.execute("""
            SELECT COUNT(*),
                   SUM(CASE WHEN lockout_until > ? THEN 1 ELSE 0 END)
            FROM users
        """, (int(time.time()),))
        row = c.fetchone() or (0, 0)
        conn.close()

        total_users = row[0] or 0
        locked_users = row[1] or 0

        success_count = 0
        failed_count = 0
        if os.path.exists('login_attempts.log'):
            with open('login_attempts.log', 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if "success" in line.lower():
                        success_count += 1
                    elif "failed" in line.lower():
                        failed_count += 1

        return jsonify({
            "success": success_count,
            "failed": failed_count,
            "total_users": total_users,
            "locked_users": locked_users
        })
    except Exception as e:
        import traceback
        print("Error in /admin_stats:", e)
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500


# -------- LOGOUT --------
@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    unset_jwt_cookies(response)
    return response


# -------- REFRESH TOKEN --------
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    response = jsonify({'msg': 'Token refreshed'})
    set_access_cookies(response, new_access_token)
    return response


# -------- START APP --------
if __name__ == '__main__':
    create_db_if_not_exists()
    # Never run with debug=True in production
    app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')