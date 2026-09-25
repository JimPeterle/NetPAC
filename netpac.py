# --------------------
#   Import library
# --------------------
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, send_from_directory
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet
import pymysql
import os
import subprocess
from dotenv import load_dotenv
import markdown
from markupsafe import Markup
from flask_bcrypt import Bcrypt
import logging
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask import abort
from flask_wtf.csrf import CSRFProtect
import tempfile
import uuid
from werkzeug.middleware.proxy_fix import ProxyFix
import re
import threading
import json
import hashlib
from cryptography.fernet import Fernet
import base64
import sys
from datetime import datetime, timedelta
import pyotp
import qrcode
import io
import shutil
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.triggers.cron import CronTrigger
import fcntl
import glob
import pwd
import signal
import time
from collections import defaultdict
from datetime import date, timedelta
from flask import jsonify
import urllib


# --------------------
#   Configuration variables
# --------------------
dir_path = os.path.dirname(os.path.realpath(__file__))
APP_VERSION = "4.0.0"
DEFAULT_PASSWORD = "admin"
db_database = "netpac_db"
SSL_CERT_DIR = "/etc/netpac/certs"
BACKUP_DIR = os.path.join(os.path.dirname(dir_path), "netpac_backups")
DB_CNF_FILE = os.path.join(dir_path, "db_secrets.cnf")


# --------------------
#   Initialize Logger 
# --------------------
logger = logging.getLogger()
file_handler = logging.FileHandler("/var/log/netpac/netpac.log", mode="a", encoding="utf-8")
logger.addHandler(file_handler)
logger.setLevel("INFO")
formatter = logging.Formatter("{asctime} - {levelname} - {message}",style="{",datefmt="%Y-%m-%d %H:%M",)
file_handler.setFormatter(formatter)

# --------------------
#   Initialize schedule logger 
# --------------------
scheduler_logger = logging.getLogger('netpac_scheduler')
scheduler_logger.propagate = False
scheduler_handler = logging.FileHandler('/var/log/netpac/scheduler.log')
scheduler_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M'))
scheduler_logger.addHandler(scheduler_handler)
scheduler_logger.setLevel(logging.INFO)

# --------------------
#   Initialize execution logger 
# --------------------
exec_logger = logging.getLogger('netpac_execution')
exec_logger.propagate = False
exec_handler = logging.FileHandler('/var/log/netpac/execution.log')
exec_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M'))
exec_logger.addHandler(exec_handler)
exec_logger.setLevel(logging.INFO)


# ---------------------------------------
#   Log level adjustment 
# ---------------------------------------
logging.getLogger('werkzeug').propagate = False

logging.getLogger('apscheduler').setLevel(logging.WARNING)

def sanitize_log(value: str) -> str:
    return value.replace('\n', ' ').replace('\r', ' ').strip()


# -------------------------------------------------
#   Filter for removce traceback logs from logfile
# -------------------------------------------------
class TracebackInfoFilter(logging.Filter):

    def __init__(self, clear=True):
        self.clear = clear
    def filter(self, record):
        if self.clear:
            record._exc_info_hidden, record.exc_info = record.exc_info, None
            record.exc_text = None
        elif hasattr(record, "_exc_info_hidden"):
            record.exc_info = record._exc_info_hidden
            del record._exc_info_hidden
        return True

file_handler.addFilter(TracebackInfoFilter())


# -----------------------------------------
#   Load .env file and map them to variable
# -----------------------------------------
load_dotenv(f"{dir_path}/secret.env")


# -----------------------------------------
#   Encryption Key Management (Used to encrypt passwords in the database)
# -----------------------------------------
def ensure_encryption_key():
    
    existing_key = os.getenv("ENCRYPTION_KEY")
    if not existing_key:
        logger.error("ENCRYPTION_KEY not found in secret.env")
        logger.error("The Secrets feature will be disabled.")
        logger.error("To use Secrets, generate a key and add to secret.env.")
        return None
    
    try:
        Fernet(existing_key.encode())
        return existing_key
    except Exception as e:
        logger.error(f"ENCRYPTION_KEY has an invalid format: {e}")
        logger.error("The Secrets feature will be disabled.")
        logger.error("To use Secrets, generate a key and add to secret.env.")
        return None

encryption_key = ensure_encryption_key()


# --------------------
#   Secret Encryption
# --------------------
class SecretEncryption:
    def __init__(self, key):

        if key is None:
            self.cipher = None
            logger.warning("Encryption NOT initialized - Secrets feature disabled")
            return
            
        try:
            self.cipher = Fernet(key.encode())
        except Exception as e:
            self.cipher = None
            logger.error(f"Error initializing encryption: {e}")
    
    def is_available(self):
        return self.cipher is not None
    
    def encrypt(self, password: str) -> str:
        if not self.is_available():
            raise ValueError("Encryption not available - ENCRYPTION_KEY is missing or invalid")
        try:
            return self.cipher.encrypt(password.encode()).decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt(self, encrypted_password: str) -> str:
        if not self.is_available():
            raise ValueError("Decryption not available - ENCRYPTION_KEY is missing or invalid")
        try:
            return self.cipher.decrypt(encrypted_password.encode()).decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise


# --------------------
#   secret.env parameter
# --------------------
encryption = SecretEncryption(encryption_key)
flask_key = os.getenv("FLASK_KEY")
db_user = os.getenv("DB_USER")
db_pw = os.getenv("DB_PW")
db_ip = os.getenv("DB_IP")
db_port = int(os.getenv("DB_PORT"))


# --------------------
#   Flask parameter
# --------------------
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = flask_key
app.config['ENV'] = 'production'
app.config['DEBUG'] = False
app.config['TESTING'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True  
app.config['SESSION_COOKIE_SECURE'] = True     
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' 
app.jinja_env.filters['fromjson'] = json.loads


# --------------------
#   Local frontend libraries (static/vendor, see update_vendor.py)
# --------------------
def load_vendor_manifest():
    try:
        with open(os.path.join(dir_path, "static", "vendor", "manifest.json"), "r", encoding="utf-8") as f:
            return {name: lib for name, lib in json.load(f).items() if not name.startswith("_")}
    except Exception as e:
        logger.error(f"Could not load static/vendor/manifest.json: {e}")
        return {}

VENDOR_LIBS = load_vendor_manifest()


_static_hashes = {}

def static_file_hash(filename):
    if filename not in _static_hashes:
        try:
            with open(os.path.join(dir_path, "static", filename), "rb") as f:
                _static_hashes[filename] = hashlib.sha256(f.read()).hexdigest()[:10]
        except OSError as e:
            logger.error(f"Could not hash static file {filename}: {e}")
            _static_hashes[filename] = APP_VERSION
    return _static_hashes[filename]


@app.context_processor
def inject_app_info():
    def static_file(filename):
        return url_for("static", filename=filename, v=static_file_hash(filename))
    return {"app_version": APP_VERSION, "static_file": static_file}


@app.context_processor
def inject_vendor():
    def vendor(name, key):
        lib = VENDOR_LIBS.get(name)
        if not lib or key not in lib.get("files", {}):
            logger.error(f"Unknown vendor file: {name}/{key}")
            return ""
        return url_for("static", filename=f"vendor/{name}-{lib['version']}/{lib['files'][key]}")
    return {"vendor": vendor}
csrf = CSRFProtect(app)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=0,
    x_prefix=0
)

def get_real_ip():
    return request.remote_addr

limiter = Limiter(
    app=app,
    key_func=get_real_ip,
    default_limits=[],
    storage_uri="memory://"
)

# --------------------
#   Define Radius
# --------------------
def load_radius_config():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT server, port, encrypted_secret, timeout FROM radius WHERE id = 1")
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return {'server_host': '', 'server_port': 1812, 'secret_set': False, 'timeout': 5}

    server_host, server_port, encrypted_secret, timeout = row
    return {
        'server_host': server_host or '',
        'server_port': server_port or 1812,
        'secret_set': bool(encrypted_secret),
        'timeout': timeout or 5
    }


def get_radius_secret():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT encrypted_secret FROM radius WHERE id = 1")
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row or not row[0]:
        return None

    try:
        return encryption.decrypt(row[0])
    except Exception as e:
        logger.error(f"Failed to decrypt RADIUS secret: {e}")
        return None


# --------------------
#   SQL Config
# --------------------
def get_db():
    return pymysql.connect(
        user=db_user,
        password=db_pw,
        host=db_ip,
        database=db_database,
        port=db_port,
        autocommit=True
)


# --------------------
#   Schedule Config
# --------------------
jobstores = {'default': SQLAlchemyJobStore(url=f'mysql+pymysql://{db_user}:{db_pw}@{db_ip}/{db_database}')}

scheduler = BackgroundScheduler(jobstores=jobstores)
scheduler.start(paused=True)
scheduler_logger.info("Scheduler initialized in paused mode (web worker) — job execution handled by netpac-scheduler.service")

def parse_schedule(expression):
    parts = expression.split()
    return {
        'minute': parts[0],
        'hour': parts[1],
        'day': parts[2],
        'month': parts[3],
        'day_of_week': parts[4]
    }

def trigger_schedule_job(job_id, script_name, user_id, target, variables, secrets_json, use_venv=False, job_type='python'):

    conn = get_db()
    cur = conn.cursor()
    vars_dict = json.loads(variables) if variables else {}
    secrets_dict = json.loads(secrets_json) if secrets_json else {}
    
    try:
        cur.execute("SELECT GET_LOCK(%s, 0)", (f"job_{script_name}",))
        lock = cur.fetchone()[0]
        
        if lock != 1:
            return

        cur.execute("SELECT is_active FROM schedule_jobs WHERE job_id = %s", (job_id,))
        active_row = cur.fetchone()
        if not active_row or not active_row[0]:
            scheduler_logger.info(f"Job {job_id} ({script_name}) is inactive in DB — removing from scheduler and skipping")
            try:
                scheduler.remove_job(str(job_id))
            except Exception:
                pass
            return

        cur.execute("""
            SELECT COUNT(*) FROM history_jobs 
            WHERE script_name = %s 
            AND status = 'running'
            AND started_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)
        """, (script_name,))
        
        if cur.fetchone()[0] > 0:
            exec_logger.info(f"Job {script_name} already running, skipping")
            return

        cur.execute("""
            INSERT INTO history_jobs 
            (script_name, user_id, target, variables, status, started_at, credential, job_type)
            VALUES (%s, %s, %s, %s, 'running', NOW(), %s, %s)
        """, (script_name, user_id, target, variables, secrets_json, job_type))
        conn.commit()
        history_job_id = cur.lastrowid
        
    finally:
        cur.execute("SELECT RELEASE_LOCK(%s)", (f"job_{script_name}",))
        cur.close()
        conn.close()

    if job_type == 'ansible':
        extra_vars = vars_dict.get('extra_vars', {})
        extra_vars_str = json.dumps(extra_vars) if extra_vars else ""
        thread = threading.Thread(
            target=execute_playbook_background,
            args=(
                history_job_id, script_name, target,
                extra_vars_str,
                secrets_dict.get('secret_1', ''),
                secrets_dict.get('secret_2', ''),
                secrets_dict.get('secret_3', '')
            )
        )
    else:
        thread = threading.Thread(
            target=execute_script_background,
            args=(
                history_job_id, script_name, target,
                variables,
                use_venv,
                secrets_dict.get('secret_1', ''),
                secrets_dict.get('secret_2', ''),
                secrets_dict.get('secret_3', '')
            )
        )

    thread.daemon = True
    thread.start()

def load_jobs_from_db():
    scheduler_logger.info("Loading jobs from DB...")
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM schedule_jobs WHERE is_active = TRUE")
        jobs = cur.fetchall()
        scheduler_logger.info(f"Found {len(jobs)} active jobs")
        cur.close()
        conn.close()

        for job in jobs:
            try:
                scheduler.add_job(
                    trigger_schedule_job,
                    trigger='cron',
                    id=str(job[0]),     
                    max_instances=1,
                    replace_existing=True,
                    kwargs={
                        'job_id': job[0],
                        'script_name': job[1],
                        'user_id': job[2],       
                        'target': job[3],      
                        'variables': job[4],    
                        'secrets_json': job[8],
                        'use_venv': bool(job[9]) if job[9] is not None else False,
                        'job_type': job[10] if len(job) > 10 and job[10] else 'python'
                    },
                    **parse_schedule(job[7])
                )
                scheduler_logger.info(f"Job-ID {job[0]} loaded: {job[1]} with schedule plan {job[7]}")
            except Exception as e:
                scheduler_logger.error(f"Error loading job {job[0]}: {e}")

    except Exception as e:
        scheduler_logger.error(f"Error in load_jobs_from_db: {e}")


# --------------------
#   Validate path
# --------------------
def is_safe_path(target: str, base_dir: str) -> bool:
    base_dir = os.path.abspath(base_dir)
    target = os.path.abspath(target)
    return target == base_dir or target.startswith(base_dir + os.sep)


# --------------------
#   Stale job cleanup
# --------------------
STALE_JOB_NO_PID_SECONDS = 600
JOB_CANCELLED_NOTE = "\n[NetPAC] Job was cancelled.\n"

def is_process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def reap_stale_jobs():
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT job_id, pid, TIMESTAMPDIFF(SECOND, started_at, NOW())
            FROM history_jobs
            WHERE status = 'running' AND finished_at IS NULL
        """)
        for job_id, pid, age in cur.fetchall():
            if pid:
                if is_process_alive(pid):
                    continue
            elif age is None or age < STALE_JOB_NO_PID_SECONDS:
                continue

            cur.execute("""
                UPDATE history_jobs
                SET status = 'failed',
                    finished_at = NOW(),
                    duration = TIMESTAMPDIFF(SECOND, started_at, NOW()),
                    output = CONCAT(COALESCE(output, ''), %s)
                WHERE job_id = %s AND status = 'running'
            """, ("\n[NetPAC] Job was interrupted (process no longer running, e.g. after a NetPAC restart).\n", job_id))
            exec_logger.warning(f"Job {job_id} marked as failed: process {pid} no longer running")
        conn.commit()
    except Exception as e:
        exec_logger.error(f"Error while cleaning up stale jobs: {e}")
    finally:
        cur.close()
        conn.close()


# --------------------
#   Validate script variable count
# --------------------
MAX_SCRIPT_VARS = 10

def parse_var_count(value) -> int:
    try:
        count = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(count, MAX_SCRIPT_VARS))


# --------------------
#   Validate password
# --------------------
def validate_password(password: str) -> str | None:
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Password must contain at least one special character"
    return None


# --------------------
#   Loginmanager
# --------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# --------------------
#   Define user
# --------------------
class User(UserMixin):
    def __init__(self, username):
        self.id = username
        self.username = username


# --------------------
#   Load user
# --------------------
@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT 1 FROM user WHERE name = %s", (user_id,))
        exists = cur.fetchone() is not None
    finally:
        cur.close()
        conn.close()
    return User(user_id) if exists else None


# --------------------
#   Login route
# --------------------
@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        auth_mode = request.form.get("auth_mode")
        

        if not username or not password:
            flash("Username and password required", "danger")
            return redirect(url_for("login"))
        
        if auth_mode == "local":
            conn = get_db()
            cur = conn.cursor()
            
            try:
                sql = "SELECT password, totp_confirmed FROM user WHERE name = %s"
                cur.execute(sql, (username,))
                row = cur.fetchone()
                
                if row is None:
                    logger.warning(f"Login attempt for non-existent user: {sanitize_log(username)}")
                    flash("Invalid login details!", "danger")
                    return redirect(url_for("login"))
                
                db_hashed_password, totp_confirmed = row
                
                if bcrypt.check_password_hash(db_hashed_password, password):
                    session["pre_auth_user"] = username

                    if not totp_confirmed:  
                        return redirect(url_for("totp_setup"))
                    else:
                        return redirect(url_for("totp_verify"))

                logger.warning(f"Failed login attempt from IP: {get_real_ip()}")
                flash("Invalid login details!", "danger")
                
            except Exception as e:
                logger.error(f"Login error: {e}")
                flash("Login error occurred!", "danger")
            finally:
                cur.close()
                conn.close()
            
            return redirect(url_for("login"))
        

        elif auth_mode == "radius":
            radius_cfg = load_radius_config()
            radius_secret = get_radius_secret()

            if not radius_cfg['server_host'] or not radius_secret:
                logger.error("RADIUS login attempted but RADIUS is not configured")
                flash("RADIUS is not configured. Contact your administrator.", "danger")
                return redirect(url_for("login"))

            try:
                srv = Client(
                    server=radius_cfg['server_host'],
                    authport=radius_cfg['server_port'],
                    secret=radius_secret.encode(),
                    dict=Dictionary(f"{dir_path}/dictionary"),
                    timeout=radius_cfg['timeout']
                )

                req = srv.CreateAuthPacket(
                    code=pyrad.packet.AccessRequest,
                    User_Name=username,
                    NAS_Identifier="NetPAC"
                )
                
                req["User-Password"] = req.PwCrypt(password)
                req.add_message_authenticator()

                reply = srv.SendPacket(req)
                
                if reply.code == pyrad.packet.AccessAccept:
                    conn = get_db()
                    cur = conn.cursor()
                    
                    try:
                        cur.execute("SELECT totp_confirmed, method FROM user WHERE name = %s", (username,))
                        row = cur.fetchone()

                        if row is not None and row[1] != 'radius':
                            logger.warning(f"RADIUS login rejected for '{sanitize_log(username)}': name belongs to a {row[1]} account (IP: {get_real_ip()})")
                            flash("Invalid login credentials", "danger")
                            return redirect(url_for("login"))

                        session["pre_auth_user"] = username

                        if row is None:
                            cur.execute(
                                "INSERT INTO user (name, password, method, totp_confirmed) VALUES (%s, NULL, 'radius', FALSE)",
                                (username,)
                            )
                            conn.commit()
                            return redirect(url_for("totp_setup"))

                        totp_confirmed = row[0]

                        if totp_confirmed:
                            return redirect(url_for("totp_verify"))
                        else:
                            return redirect(url_for("totp_setup"))

                    finally:
                        cur.close()
                        conn.close()
                
                logger.warning(f"Failed login attempt from IP: {get_real_ip()}")
                flash("Invalid login credentials", "danger")
                
            except Exception as e:
                logger.error(f"RADIUS error: {e}")
                flash("Login error occurred!", "danger")
            
            return redirect(url_for("login"))
    
    return render_template("login.html")


# --------------------
#   TOTP setup route
# --------------------
@app.route("/totp/setup", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def totp_setup():
    if "pre_auth_user" not in session:
        return redirect(url_for("login"))

    username = session["pre_auth_user"]

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT totp_confirmed FROM user WHERE name = %s", (username,))
        row = cur.fetchone()
    finally:
        cur.close()
        conn.close()

    if row is None:
        session.clear()
        return redirect(url_for("login"))

    if row[0]:
        return redirect(url_for("totp_verify"))

    if request.method == "POST":
        code = request.form.get("code", "")
        secret = session.get("totp_secret_temp")

        if not secret:
            return redirect(url_for("totp_setup"))

        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            conn = get_db()
            cur = conn.cursor()
            cur.execute("UPDATE user SET totp_secret = %s, totp_confirmed = TRUE WHERE name = %s AND NOT COALESCE(totp_confirmed, FALSE)", (secret, username))
            updated = cur.rowcount
            conn.commit()

            if updated != 1:
                cur.close()
                conn.close()
                session.clear()
                return redirect(url_for("login"))

            cur.execute("SELECT method FROM user WHERE name = %s", (username,))
            row = cur.fetchone()
            method = row[0] if row else "unknown"
            
            cur.close()
            conn.close()

            session.pop("totp_secret_temp", None)
            session.pop("pre_auth_user", None)
            user = User(username)
            login_user(user)
            session.permanent = True
            logger.info(f"Successful TOTP setup and login: {sanitize_log(username)} (method: {method})")
            return redirect(url_for("dashboard"))
        
        else:
            flash("Invalid code, try again", "warning")

    if "totp_secret_temp" not in session:
        session["totp_secret_temp"] = pyotp.random_base32()

    secret = session["totp_secret_temp"]
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="NetPAC")

    favicon_url = url_for('static', filename='favicon.png', _external=True)
    uri += "&image=" + urllib.parse.quote(favicon_url, safe='')

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template("totp_setup.html", qr_b64=qr_b64, secret=secret)


# ------------------------
#   TOTP for existing user
# ------------------------
@app.route("/totp/verify", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def totp_verify():
    if "pre_auth_user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        if request.form.get("cancel"):
            session.clear()
            return redirect(url_for("login"))

        code = request.form.get("code")
        username = session["pre_auth_user"]

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT totp_secret, method FROM user WHERE name = %s", (username,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        
        if not row or not row[0]:
            session.clear()
            return redirect(url_for("login"))

        method = row[1]

        totp = pyotp.TOTP(row[0])
        if totp.verify(code or ""):
            session.pop("pre_auth_user", None)
            user = User(username)
            login_user(user)
            session.permanent = True
            logger.info(f"Successful login: {sanitize_log(username)} (method: {method})")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid code", "danger")

    return render_template("totp_verify.html")


# --------------------
#   TOTP abort
# --------------------
@app.route("/totp/abort", methods=["POST"])
def totp_abort():
    session.clear()
    return redirect(url_for("login"))


# --------------------
#   Favicon
# --------------------
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', mimetype='image/vnd.microsoft.icon')


# --------------------
#   Dashboard route
# --------------------
@app.route("/dashboard")
@login_required
def dashboard():
    def load_md(filename):
        path = os.path.join(dir_path, "static", filename)
        try:
            with open(path, "r") as f:
                return markdown.markdown(f.read(), extensions=['fenced_code', 'tables'])
        except FileNotFoundError:
            return ""

    md_python = load_md("dashboard_python.md")
    md_ansible = load_md("dashboard_ansible.md")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM hosts")
    all_hosts = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM host_groups")
    all_groups = cur.fetchone()[0]

    cur.execute("""
        SELECT DATE(started_at) as day, job_type, COUNT(*) as count
        FROM history_jobs
        WHERE started_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY DATE(started_at), job_type
        ORDER BY day ASC
    """)
    jobs_per_day_raw = cur.fetchall()

    cur.execute("""
        SELECT status, job_type, COUNT(*) as count
        FROM history_jobs
        GROUP BY status, job_type
    """)
    status_raw = cur.fetchall()

    cur.execute("""
        SELECT script_name, COUNT(*) as count
        FROM history_jobs
        WHERE job_type = 'python' OR job_type IS NULL
        GROUP BY script_name
        ORDER BY count DESC
        LIMIT 5
    """)
    top_scripts = cur.fetchall()

    cur.execute("""
        SELECT script_name, COUNT(*) as count
        FROM history_jobs
        WHERE job_type = 'ansible'
        GROUP BY script_name
        ORDER BY count DESC
        LIMIT 5
    """)
    top_playbooks = cur.fetchall()

    cur.execute("""
        SELECT job_id, script_name, started_at, job_type
        FROM history_jobs
        WHERE status = 'failed'
        ORDER BY started_at DESC
        LIMIT 5
    """)
    last_failed = cur.fetchall()

    cur.close()
    conn.close()

    days = [(date.today() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
    jobs_per_day = {d: {'python': 0, 'ansible': 0} for d in days}
    for row in jobs_per_day_raw:
        day = str(row[0])
        jtype = row[1] or 'python'
        if day in jobs_per_day:
            jobs_per_day[day][jtype] = row[2]

    stats = {
        'python': {'completed': 0, 'failed': 0, 'timeout': 0},
        'ansible': {'completed': 0, 'failed': 0, 'timeout': 0}
    }
    for row in status_raw:
        jtype = row[1] or 'python'
        if jtype in stats and row[0] in stats[jtype]:
            stats[jtype][row[0]] = row[2]

    return render_template("dashboard.html",
        md_python=md_python,
        md_ansible=md_ansible,
        all_hosts=all_hosts,
        all_groups=all_groups,
        days=days,
        jobs_per_day=jobs_per_day,
        stats=stats,
        top_scripts=top_scripts,
        top_playbooks=top_playbooks,
        last_failed=last_failed
    )


# --------------------
#   Groups route
# --------------------
@app.route("/groups")
@login_required
def groups():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT g.group_id, g.name, COUNT(m.host_id) as host_count, g.ansible_vars
        FROM host_groups g
        LEFT JOIN host_group_membership m ON g.group_id = m.group_id
        GROUP BY g.group_id, g.name, g.ansible_vars
        ORDER BY g.name
    """)
    groups = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("groups.html", groups=groups)


@app.route("/groups", methods=["POST"])
@login_required
def add_group():
    name = request.form.get("name", "").strip()
    ansible_vars = request.form.get("ansible_vars", "").strip()

    if not name:
        flash("Group name is required", "danger")
        return redirect(url_for("groups"))

    if not re.match(r'^[a-zA-Z0-9_]+$', name):
        flash("Group name can only contain letters, numbers, and underscores (no spaces or special characters)", "danger")
        return redirect(url_for("groups"))

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO host_groups (name, ansible_vars) VALUES (%s, %s)", (name, ansible_vars))
        conn.commit()
        logger.info(f"Group '{sanitize_log(name)}' created by {current_user.id}")
        flash(f"Group '{name}' created", "success")
    except pymysql.IntegrityError:
        flash(f"Group '{name}' already exists", "danger")
    except Exception as e:
        logger.error(f"Error creating group: {e}")
        flash("Error creating group", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("groups"))


@app.route("/groups/edit/<int:group_id>", methods=["POST"])
@login_required
def edit_group(group_id):
    ansible_vars = request.form.get("ansible_vars", "").strip()

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT name FROM host_groups WHERE group_id = %s", (group_id,))
        row = cur.fetchone()
        if not row:
            flash("Group not found", "danger")
            return redirect(url_for("groups"))

        cur.execute(
            "UPDATE host_groups SET ansible_vars = %s WHERE group_id = %s",
            (ansible_vars, group_id)
        )
        conn.commit()
        flash(f"Group '{row[0]}' updated", "success")
    except Exception as e:
        logger.error(f"Error updating group: {e}")
        conn.rollback()
        flash("Error updating group", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("groups"))


@app.route("/groups/delete", methods=["POST"])
@login_required
def delete_group():
    group_id = request.form.get("group_id", "").strip()

    if not group_id:
        return redirect(url_for("groups"))

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT name FROM host_groups WHERE group_id = %s", (group_id,))
        row = cur.fetchone()
        if not row:
            flash("Group not found", "warning")
            return redirect(url_for("groups"))

        cur.execute("DELETE FROM host_groups WHERE group_id = %s", (group_id,))
        conn.commit()
        logger.info(f"Group '{sanitize_log(row[0])}' deleted by {current_user.id}")
        flash(f"Group '{row[0]}' deleted", "success")
    except Exception as e:
        logger.error(f"Error deleting group: {e}")
        conn.rollback()
        flash("Error deleting group", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("groups"))


def load_host_group_names(cur, group_id=None):
    sql = """
        SELECT h.hostname, COALESCE(GROUP_CONCAT(g.name ORDER BY g.name SEPARATOR ','), '')
        FROM hosts h
        LEFT JOIN host_group_membership m ON h.host_id = m.host_id
        LEFT JOIN host_groups g ON m.group_id = g.group_id
    """
    params = ()
    if group_id is not None:
        sql += " WHERE h.host_id IN (SELECT host_id FROM host_group_membership WHERE group_id = %s)"
        params = (group_id,)
    sql += " GROUP BY h.host_id, h.hostname"
    cur.execute(sql, params)
    return {row[0]: row[1] for row in cur.fetchall()}


# ------------------------
#   Hosts by Group route
# ------------------------
@app.route("/hosts/<int:group_id>")
@login_required
def hosts_by_group(group_id):
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT name FROM host_groups WHERE group_id = %s", (group_id,))
        group_row = cur.fetchone()
        if not group_row:
            abort(404)
        group_name = group_row[0]

        cur.execute("""
            SELECT h.host_id, h.hostname, h.description
            FROM hosts h
            JOIN host_group_membership m ON h.host_id = m.host_id
            WHERE m.group_id = %s
            ORDER BY h.hostname
        """, (group_id,))
        all_hosts = cur.fetchall()

        host_groups = load_host_group_names(cur, group_id)

        cur.execute("SELECT group_id, name, ansible_vars FROM host_groups ORDER BY name")
        available_groups = cur.fetchall()

    except Exception as e:
        logger.error(f"Exception on hosts_by_group: {type(e).__name__}: {e}")
        all_hosts = []
        host_groups = {}
        group_name = ""
        available_groups = []
    finally:
        cur.close()
        conn.close()

    return render_template("hosts.html", hosts=all_hosts, host_groups=host_groups, filtered_group=group_name, available_groups=available_groups)


# --------------------
#   Hosts route
# --------------------
@app.route("/hosts")
@login_required
def hosts():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT host_id, hostname, description FROM hosts ORDER BY hostname")
    all_hosts = cur.fetchall()

    host_groups = load_host_group_names(cur)

    cur.execute("SELECT group_id, name, ansible_vars FROM host_groups ORDER BY name")
    available_groups = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("hosts.html", hosts=all_hosts, host_groups=host_groups, available_groups=available_groups)


@app.route("/hosts", methods=["POST"])
@login_required
def add_host():
    hostname = request.form.get("Hostname", "").strip()
    description = request.form.get("Description", "").strip()
    group_ids = request.form.getlist("group_ids")

    if not hostname:
        flash("Hostname is required", "danger")
        return redirect(url_for("hosts"))

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT COUNT(*) FROM hosts WHERE hostname = %s", (hostname,))
        if cur.fetchone()[0] > 0:
            flash(f"Host '{hostname}' already exists", "danger")
            return redirect(url_for("hosts"))

        conn.begin()
        cur.execute("INSERT INTO hosts (hostname, description) VALUES (%s, %s)", (hostname, description))
        host_id = cur.lastrowid

        for gid in group_ids:
            if gid:
                cur.execute("INSERT INTO host_group_membership (host_id, group_id) VALUES (%s, %s)", (host_id, gid))

        conn.commit()
        logger.info(f"Host {hostname} added with groups {group_ids} by {current_user.id}")
        flash(f"Host '{hostname}' added", "success")

    except pymysql.IntegrityError as e:
        logger.error(f"IntegrityError on /hosts [POST]: {e}")
        conn.rollback()
        flash("Error adding host", "danger")
    except Exception as e:
        logger.error(f"Exception on /hosts [POST]: {type(e).__name__}: {e}")
        conn.rollback()
        flash("Error adding host", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("hosts"))


@app.route("/update_host", methods=["POST"])
@login_required
def update_host():
    original_hostname = request.form.get("OriginalHostname", "").strip()
    hostname = request.form.get("Hostname", "").strip()
    description = request.form.get("Description", "").strip()
    group_ids = request.form.getlist("group_ids")

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT host_id FROM hosts WHERE hostname = %s", (original_hostname,))
        row = cur.fetchone()
        if not row:
            flash("Host not found", "danger")
            return redirect(url_for("hosts"))
        host_id = row[0]

        conn.begin()
        cur.execute("UPDATE hosts SET hostname = %s, description = %s WHERE host_id = %s", (hostname, description, host_id))

        cur.execute("DELETE FROM host_group_membership WHERE host_id = %s", (host_id,))
        for gid in group_ids:
            if gid:
                cur.execute("INSERT INTO host_group_membership (host_id, group_id) VALUES (%s, %s)", (host_id, gid))

        conn.commit()
        logger.info(f"Host {hostname} updated with groups {group_ids}")
        flash(f"Host '{hostname}' updated", "success")

    except Exception as e:
        logger.error(f"Exception on update_host: {type(e).__name__}: {e}")
        conn.rollback()
        flash("Error updating host", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("hosts"))


@app.route("/hosts/delete", methods=["POST"])
@login_required
def delete_host():
    hostname = request.form.get("hostname", "").strip()

    if not hostname:
        return redirect(url_for("hosts"))

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT host_id FROM hosts WHERE hostname = %s", (hostname,))
        row = cur.fetchone()
        if not row:
            return redirect(url_for("hosts"))

        cur.execute("DELETE FROM hosts WHERE host_id = %s", (row[0],))
        conn.commit()
        logger.info(f"Host {hostname} successfully deleted")

    except Exception as e:
        logger.error(f"Error deleting host {hostname}: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("hosts"))


# ---------------------
#   Git Config
# ---------------------
GIT_CONFIG_FILE = f"{dir_path}/git_config.json"

def load_git_config():
    if os.path.exists(GIT_CONFIG_FILE):
        try:
            with open(GIT_CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"repo_url": "", "branch": "main", "token_encrypted": ""}


def build_git_env(token: str) -> dict:
    env = os.environ.copy()
    env['GIT_TERMINAL_PROMPT'] = '0'
    if token:
        basic = base64.b64encode(f"oauth2:{token}".encode()).decode()
        env['GIT_CONFIG_COUNT'] = '1'
        env['GIT_CONFIG_KEY_0'] = 'http.extraHeader'
        env['GIT_CONFIG_VALUE_0'] = f"Authorization: Basic {basic}"
    return env


# --------------------
#   Scripts
# --------------------
@app.route("/scripts")
@login_required
def scripts():
    base_dir = "/var/lib/netpac/scripts"
    git_dir = "/var/lib/netpac/git"
    git_config = load_git_config()

    entries = []
    if not os.path.isdir(base_dir):
        logger.error(f"Script directory {base_dir} does not exist")
        flash(f"Script directory {base_dir} does not exist — run setup.sh again or create it", "warning")

    for name in (sorted(os.listdir(base_dir)) if os.path.isdir(base_dir) else []):
        full = os.path.join(base_dir, name)
        if os.path.isdir(full) or name.endswith('.py'):
            entries.append({
                "name": name,
                "is_dir": os.path.isdir(full),
                "path": name
            })

    if os.path.exists(git_dir):
        entries.append({
            "name": "git",
            "is_dir": True,
            "path": "git"
        })

    all_scripts = []
    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d != '.git']
        for file in sorted(files):
            if file.endswith('.py'):
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, base_dir)
                all_scripts.append({"name": file, "path": relative_path, "is_dir": False})

    if os.path.exists(git_dir):
        for root, dirs, files in os.walk(git_dir):
            dirs[:] = [d for d in dirs if d != '.git']
            for file in sorted(files):
                if file.endswith('.py'):
                    full_path = os.path.join(root, file)
                    relative_path = "git/" + os.path.relpath(full_path, git_dir)
                    all_scripts.append({"name": file, "path": relative_path, "is_dir": False})

    all_scripts = sorted(all_scripts, key=lambda x: x['path'])

    return render_template("scripts.html", entries=entries, git_config=git_config, current_path="", all_scripts=all_scripts)


@app.route("/scripts/", defaults={"subpath": ""})
@app.route("/scripts/<path:subpath>")
@login_required
def view_script(subpath):
    scripts_base = os.path.abspath("/var/lib/netpac/scripts")
    git_base = os.path.abspath("/var/lib/netpac/git")

    if subpath == "git" or subpath.startswith("git/"):
        base_dir = git_base
        rel_subpath = subpath[len("git"):].lstrip("/")
    else:
        base_dir = scripts_base
        rel_subpath = subpath

    target = os.path.abspath(os.path.join(base_dir, rel_subpath))

    if not is_safe_path(target, base_dir):
        logger.warning(f"Path traversal attempt detected: {subpath}")
        abort(403)

    if not os.path.exists(target):
        abort(404)

    if os.path.isdir(target):
        entries = []
        for name in sorted(os.listdir(target)):
            if name == '.git':
                continue
            full = os.path.join(target, name)
            entries.append({
                "name": name,
                "is_dir": os.path.isdir(full),
                "path": os.path.join(subpath, name) if subpath else name
            })
        return render_template("scripts.html", entries=entries, current_path=subpath, git_config=load_git_config())

    try:
        with open(target, "r", encoding="utf-8") as f:
            content = f.read()

        secrets = []
        if encryption.is_available():
            conn = get_db()
            cur = conn.cursor()
            try:
                cur.execute("SELECT name, username FROM secrets ORDER BY name")
                secrets = [{'name': row[0], 'username': row[1]} for row in cur.fetchall()]
            finally:
                cur.close()
                conn.close()

        return render_template("view_script.html", filename=subpath, content=content, secrets=secrets)

    except Exception as e:
        logger.error(f"Error reading script {subpath}: {e}")
        abort(500)


@app.route("/run_scripts/<path:subpath>", methods=["POST"])
@login_required
def run_script(subpath):
    base_dir = os.path.abspath("/var/lib/netpac/scripts")
    target_path = os.path.abspath(os.path.join(base_dir, subpath))
       
    if not is_safe_path(target_path, base_dir):
        logger.warning(f"Path traversal attempt detected: {subpath}")
        abort(403)
    
    reap_stale_jobs()

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM history_jobs WHERE script_name = %s AND status = 'running'", (subpath,))
    running = cur.fetchone()[0]
    cur.close()
    conn.close()

    if running > 0:
        flash(f"Script '{subpath}' is already running. Please wait for it to finish.", "danger")
        return redirect(url_for("history"))
    
    safe_filename = subpath
    
    target = request.form.get("target", "").strip()
    secret_1 = request.form.get("secret_1", "").strip()
    secret_2 = request.form.get("secret_2", "").strip()
    secret_3 = request.form.get("secret_3", "").strip()
    var_count = parse_var_count(request.form.get("varCount"))
    vars_dict = {"varCount": var_count}
    for i in range(1, var_count + 1):
        vars_dict[f"variable{i}"] = request.form.get(f"variable{i}", "").strip()

    variables = json.dumps(vars_dict)

    secrets_json = {
        "secret_1": secret_1,
        "secret_2": secret_2,
        "secret_3": secret_3
    }
    
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO history_jobs 
            (script_name, user_id, target, variables, status, started_at, credential, job_type) 
            VALUES (%s, %s, %s, %s, 'running', NOW(), %s, 'python')
        """, (safe_filename, current_user.id, target, variables, json.dumps(secrets_json)))
        
        conn.commit()
        job_id = cur.lastrowid
        
    except Exception as e:
        logger.error(f"Failed to create job: {e}")
        conn.rollback()
        return redirect(url_for("scripts"))
    finally:
        cur.close()
        conn.close()

    use_venv = request.form.get("use_venv") == "on"

    thread = threading.Thread(
        target=execute_script_background,
        args=(job_id, safe_filename, target, variables, use_venv, secret_1, secret_2, secret_3)
    )

    thread.daemon = True
    thread.start()

    flash(f"Script '{safe_filename}' started (Job #{job_id})", "success")
    return redirect(url_for("history", mode="python"))


# --------------------
#   Background Script execution
# --------------------
def execute_script_background(job_id, filename, target, variables, use_venv, secret_1, secret_2, secret_3):

    exec_logger.info(f"Background executing: {filename}")

    venv_python = os.path.join(dir_path, 'venv', 'bin', 'python3')
    system_python = shutil.which("python3") or "/usr/bin/python3"
    python = venv_python if use_venv and os.path.exists(venv_python) else system_python
    
    vars_dict = json.loads(variables) if isinstance(variables, str) else variables
    var_count = int(vars_dict.get("varCount", 0))
    
    start_time = datetime.now()
    output_script = ""
    status = "completed"
    temp_hostfile = None
    env = os.environ.copy()
    env['PATH'] = '/usr/bin:/usr/local/bin:' + env.get('PATH', '')
    env['PYTHONUNBUFFERED'] = '1'

    process = None 

    conn = get_db()
    cur = conn.cursor()

    def append_live_output(text):
        try:
            live_conn = get_db()
            live_cur = live_conn.cursor()
            live_cur.execute(
                "UPDATE history_jobs SET output = CONCAT(COALESCE(output, ''), %s) WHERE job_id = %s",
                (text, job_id)
            )
            live_conn.commit()
            live_cur.close()
            live_conn.close()
        except Exception as e:
            exec_logger.error(f"Failed to update live output for job {job_id}: {e}")

    output_lines = []

    try:
        if target:
            resolved = set()
            for item in target.split(","):
                item = item.strip()
                if not item:
                    continue

                cur.execute("""
                    SELECT DISTINCT h.hostname FROM hosts h
                    JOIN host_group_membership m ON h.host_id = m.host_id
                    JOIN host_groups g ON m.group_id = g.group_id
                    WHERE g.name = %s
                """, (item,))
                group_matches = cur.fetchall()

                if group_matches:
                    resolved.update(row[0] for row in group_matches)
                else:
                    cur.execute("SELECT DISTINCT hostname FROM hosts WHERE hostname = %s", (item,))
                    host_match = cur.fetchall()
                    if host_match:
                        resolved.update(row[0] for row in host_match)
                    else:
                        raise ValueError(f"Target '{item}' not found in database")

            targets = [(h,) for h in sorted(resolved)]
        else:
            targets = []

        for num, secret in enumerate([secret_1, secret_2, secret_3], 1):
            if secret:
                cur.execute("SELECT username, encrypted_password FROM secrets WHERE name = %s", (secret,))
                row = cur.fetchone()
                if not row:
                    raise ValueError(f"Secret '{secret}' not found (deleted or renamed?)")
                username, password_enc = row
                decrypted = encryption.decrypt(password_enc)
                env[f'SECRET_{num}_USERNAME'] = username
                env[f'SECRET_{num}_PASSWORD'] = decrypted

        temp_hostfile = tempfile.gettempdir() + f"/netpac_hosts_{uuid.uuid4().hex}.txt"
        with open(temp_hostfile, "w") as f:
            for t in targets:
                f.write(t[0] + "\n")

        base_dir_scripts = os.path.realpath("/var/lib/netpac/scripts")
        git_base = os.path.realpath("/var/lib/netpac/git")

        if filename == "git" or filename.startswith("git/"):
            base_dir = git_base
            rel_filename = filename[len("git"):].lstrip("/")
        else:
            base_dir = base_dir_scripts
            rel_filename = filename

        script_path = os.path.realpath(os.path.join(base_dir, rel_filename))

        if not is_safe_path(script_path, base_dir):
            raise ValueError("Invalid script path")

        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Script not found: {filename}")

        env['NETPAC_HOSTFILE'] = temp_hostfile
        script_dir = os.path.dirname(os.path.abspath(script_path))

        args = [python, '-u', script_path]
        for i in range(1, var_count + 1):
            args.append(vars_dict.get(f'variable{i}', ''))

        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env, cwd=script_dir,
            start_new_session=True
        )

        try:
            pid_conn = get_db()
            pid_cur = pid_conn.cursor()
            pid_cur.execute("UPDATE history_jobs SET pid = %s WHERE job_id = %s", (process.pid, job_id))
            pid_conn.commit()
            pid_cur.close()
            pid_conn.close()
        except Exception as e:
            exec_logger.error(f"Failed to store PID for job {job_id}: {e}")

        last_update = time.time()
        flushed = 0

        for line in process.stdout:
            output_lines.append(line)
            if time.time() - last_update >= 1:
                append_live_output("".join(output_lines[flushed:]))
                flushed = len(output_lines)
                last_update = time.time()

        process.wait()
        output_script = "".join(output_lines)

        if process.returncode != 0:
            status = "failed"

    except Exception as e:
        status = "failed"
        output_script = f"ERROR: {str(e)}"
        exec_logger.error(f"Unexpected error in background script: {e}")

    finally:
        if temp_hostfile and os.path.exists(temp_hostfile):
            os.remove(temp_hostfile)

        end_time = datetime.now()
        duration = int((end_time - start_time).total_seconds())

        try:
            cur.execute("""
                UPDATE history_jobs 
                SET status = IF(status = 'cancelled', 'cancelled', %s),
                    output = IF(status = 'cancelled', CONCAT(%s, %s), %s),
                    finished_at = NOW(), duration = %s
                WHERE job_id = %s
            """, (status, output_script, JOB_CANCELLED_NOTE, output_script, duration, job_id))
            conn.commit()
        except Exception as e:
            exec_logger.error(f"Failed to update job {job_id}: {e}")
            conn.rollback()
        finally:
            cur.close()
            conn.close()


# --------------------
#   VENV
# --------------------
VENV_DIR = os.path.join(dir_path, 'venv')
VENV_PIP = os.path.join(VENV_DIR, 'bin', 'pip')

@app.route("/venv")
@login_required
def venv_manager():
    packages = []
    venv_exists = os.path.exists(VENV_PIP)
    
    if venv_exists:
        env = os.environ.copy()
        env['PATH'] = '/usr/bin:/usr/local/bin:' + env.get('PATH', '')

        result = subprocess.run(
            [VENV_PIP, 'list', '--format=json'],
            capture_output=True, text=True,
            env=env
        )
        if result.returncode == 0:
            packages = json.loads(result.stdout)

    return render_template("venv.html", packages=packages, venv_exists=venv_exists)


@app.route("/venv/install", methods=["POST"])
@login_required
def venv_install():
    package = request.form.get("package", "").strip()
    
    if not package:
        flash("Package name required", "danger")
        return redirect(url_for("venv_manager"))

    if not re.match(r'^[a-zA-Z0-9_\-\.\[\]>=<!]+$', package):
        flash("Invalid package name", "danger")
        return redirect(url_for("venv_manager"))

    env = os.environ.copy()
    env['PATH'] = '/usr/bin:/usr/local/bin:' + env.get('PATH', '')

    result = subprocess.run(
        [VENV_PIP, 'install', package],
        capture_output=True, text=True,
        env=env
    )

    if result.returncode == 0:
        flash(f"Package '{package}' installed successfully", "success")
    else:
        flash(f"Failed to install '{package}': {result.stderr}", "danger")

    return redirect(url_for("venv_manager"))


@app.route("/venv/uninstall", methods=["POST"])
@login_required
def venv_uninstall():
    package = request.form.get("package", "").strip()

    if not package:
        flash("Package name required", "danger")
        return redirect(url_for("venv_manager"))

    env = os.environ.copy()
    env['PATH'] = '/usr/bin:/usr/local/bin:' + env.get('PATH', '')

    result = subprocess.run(
        [VENV_PIP, 'uninstall', '-y', package],
        capture_output=True, text=True,
        env=env
    )

    if result.returncode == 0:
        flash(f"Package '{package}' removed", "success")
    else:
        flash(f"Failed to remove '{package}': {result.stderr}", "danger")

    return redirect(url_for("venv_manager"))


@app.route("/venv/update", methods=["POST"])
@login_required
def venv_update():
    package = request.form.get("package", "").strip()

    if not package:
        flash("Package name required", "danger")
        return redirect(url_for("venv_manager"))

    env = os.environ.copy()
    env['PATH'] = '/usr/bin:/usr/local/bin:' + env.get('PATH', '')

    result = subprocess.run(
        [VENV_PIP, 'install', '--upgrade', package],
        capture_output=True, text=True,
        env=env
    )

    if result.returncode == 0:
        flash(f"Package '{package}' updated", "success")
    else:
        flash(f"Failed to update '{package}': {result.stderr}", "danger")

    return redirect(url_for("venv_manager"))


@app.route("/venv/update_all", methods=["POST"])
@login_required
def venv_update_all():
    env = os.environ.copy()
    env['PATH'] = '/usr/bin:/usr/local/bin:' + env.get('PATH', '')

    result = subprocess.run(
        [VENV_PIP, 'list', '--outdated', '--format=json'],
        capture_output=True, text=True,
        env=env
    )
    
    if result.returncode == 0:
        outdated = json.loads(result.stdout)
        for pkg in outdated:
            subprocess.run(
                [VENV_PIP, 'install', '--upgrade', pkg['name']],
                capture_output=True, text=True,
                env=env
            )
        flash(f"Updated {len(outdated)} packages", "success")
    else:
        flash("Failed to check for updates", "danger")

    return redirect(url_for("venv_manager"))


# ---------------------
#   Scripts Git Sync
# ---------------------
@app.route("/scripts/sync", methods=["POST"])
@login_required
def sync_scripts():
    git_config  = load_git_config()
    repo_url    = git_config.get("repo_url", "")
    branch      = git_config.get("branch", "main")
    token_enc   = git_config.get("token_encrypted", "")
    git_dir = "/var/lib/netpac/git"

    if not repo_url:
        flash("No Git repository has been configured. Please set it up in the settings first.", "warning")
        return redirect(url_for("scripts"))
    
    token = ""
    if token_enc and encryption.is_available():
        try:
            token = encryption.decrypt(token_enc)
        except Exception as e:
            logger.error(f"Error decrypting git token: {e}")
            flash("Error decrypting git token", "danger")
            return redirect(url_for("scripts"))

    git_env = build_git_env(token)

    try:
        is_git_repo = os.path.isdir(os.path.join(git_dir, ".git"))

        if is_git_repo:
            subprocess.run(
                ["/usr/bin/git", "remote", "set-url", "origin", repo_url],
                capture_output=True, text=True, timeout=10,
                cwd=git_dir, env=git_env
            )
            result = subprocess.run(
                ["/usr/bin/git", "pull", "origin", branch],
                capture_output=True, text=True, timeout=60,
                cwd=git_dir, env=git_env
            )
        else:
            result = subprocess.run(
                ["/usr/bin/git", "clone", "--branch", branch, repo_url, git_dir],
                capture_output=True, text=True, timeout=120, env=git_env
            )

        if result.returncode == 0:
            logger.info(f"Git sync successful by {current_user.id}: {repo_url} @ {branch}")
            flash("Git sync successful", "success")
        else:
            safe_stderr = result.stderr.replace(token, "***") if token else result.stderr
            logger.error(f"Git sync failed for {current_user.id}: {safe_stderr}")
            flash(f"Sync failed: {safe_stderr.strip()}", "danger")

    except subprocess.TimeoutExpired:
        flash("Git sync timed out", "danger")
    except Exception as e:
        safe_err = str(e).replace(token, "***") if token else str(e)
        logger.error(f"Git sync error: {safe_err}")
        flash(f"Error sync: {safe_err}", "danger")

    return redirect(url_for("scripts"))


# ---------------------
#   Playbooks
# ---------------------
@app.route("/playbooks/", defaults={"subpath": ""})
@app.route("/playbooks/<path:subpath>")
@login_required
def browse_playbooks(subpath):
    playbooks_base = os.path.realpath("/var/lib/netpac/playbooks")
    git_base = os.path.realpath("/var/lib/netpac/git")

    if subpath == "git" or subpath.startswith("git/"):
        base_dir = git_base
        rel_subpath = subpath[len("git"):].lstrip("/")
    else:
        base_dir = playbooks_base
        rel_subpath = subpath

    target = os.path.realpath(os.path.join(base_dir, rel_subpath))

    if not is_safe_path(target, base_dir):
        logger.warning(f"Path traversal attempt detected: {subpath}")
        abort(403)

    if subpath == "" and not os.path.isdir(target):
        logger.error(f"Playbook directory {target} does not exist")
        flash(f"Playbook directory {target} does not exist — run setup.sh again or create it", "warning")
    elif not os.path.exists(target):
        abort(404)

    if subpath == "" or os.path.isdir(target):
        entries = []
        for name in (sorted(os.listdir(target)) if os.path.isdir(target) else []):
            if name == '.git':
                continue
            full = os.path.join(target, name)
            entries.append({
                "name": name,
                "is_dir": os.path.isdir(full),
                "path": os.path.join(subpath, name) if subpath else name
            })

        if subpath == "" and os.path.exists(git_base):
            entries.append({
                "name": "git",
                "is_dir": True,
                "path": "git"
            })

        all_playbooks = []

        for root, dirs, files in os.walk(playbooks_base):
            dirs[:] = [d for d in dirs if d != '.git']
            for file in sorted(files):
                if file.endswith('.yml') or file.endswith('.yaml'):
                    full_path = os.path.join(root, file)
                    relative_path = os.path.relpath(full_path, playbooks_base)
                    all_playbooks.append({
                        "name": file,
                        "path": relative_path,
                        "is_dir": False
                    })

        if os.path.exists(git_base):
            for root, dirs, files in os.walk(git_base):
                dirs[:] = [d for d in dirs if d != '.git']
                for file in sorted(files):
                    if file.endswith('.yml') or file.endswith('.yaml'):
                        full_path = os.path.join(root, file)
                        relative_path = "git/" + os.path.relpath(full_path, git_base)
                        all_playbooks.append({
                            "name": file,
                            "path": relative_path,
                            "is_dir": False
                        })

        all_playbooks = sorted(all_playbooks, key=lambda x: x['path'])

        secrets = []
        if encryption.is_available():
            conn = get_db()
            cur = conn.cursor()
            try:
                cur.execute("SELECT name, username FROM secrets ORDER BY name")
                secrets = [{'name': r[0], 'username': r[1]} for r in cur.fetchall()]
            finally:
                cur.close()
                conn.close()

        return render_template("playbooks.html", entries=entries, all_playbooks=all_playbooks, secrets=secrets, current_path=subpath, git_config=load_git_config())

    elif os.path.isfile(target) and (target.endswith('.yml') or target.endswith('.yaml')):
        try:
            with open(target, "r", encoding="utf-8") as f:
                content = f.read()

            secrets = []
            if encryption.is_available():
                conn = get_db()
                cur = conn.cursor()
                try:
                    cur.execute("SELECT name, username FROM secrets ORDER BY name")
                    secrets = [{'name': r[0], 'username': r[1]} for r in cur.fetchall()]
                finally:
                    cur.close()
                    conn.close()

            return render_template("view_playbook.html", filename=subpath, content=content, secrets=secrets)

        except Exception as e:
            logger.error(f"Error reading playbook {subpath}: {e}")
            abort(500)

    abort(404)


@app.route("/playbook_graph/<path:subpath>", methods=["POST"])
@login_required
def playbook_graph(subpath):
    playbooks_base = os.path.realpath("/var/lib/netpac/playbooks")
    git_base = os.path.realpath("/var/lib/netpac/git")

    if subpath == "git" or subpath.startswith("git/"):
        base_dir = git_base
        rel_subpath = subpath[len("git"):].lstrip("/")
    else:
        base_dir = playbooks_base
        rel_subpath = subpath

    target = os.path.realpath(os.path.join(base_dir, rel_subpath))

    if not is_safe_path(target, base_dir):
        logger.warning(f"Path traversal attempt detected: {subpath}")
        abort(403)

    graph_dir = "/var/lib/netpac/graphs"
    os.makedirs(graph_dir, exist_ok=True)
    
    graph_name = subpath.replace("/", "_").replace(".yml", "").replace(".yaml", "")
    output_path = os.path.join(graph_dir, graph_name)

    grapher = os.path.join(dir_path, "venv", "bin", "ansible-playbook-grapher")

    if not os.path.exists(grapher) and not shutil.which("ansible-playbook-grapher"):
        flash("ansible-playbook-grapher is not installed. Install it manually over the Web-Interface -> Python -> Environment", "danger")
        return redirect(url_for("browse_playbooks", subpath=subpath))
    
    env = os.environ.copy()
    env['PATH'] = '/usr/bin:/usr/local/bin:' + env.get('PATH', '')

    result = subprocess.run(
        [grapher, target, "-o", output_path],
        capture_output=True, text=True,
        env=env
    )

    if result.returncode != 0:
        flash(f"Graph generation failed: {result.stderr}", "danger")
        return redirect(url_for("browse_playbooks", subpath=subpath))

    return redirect(url_for("view_playbook_graph", filename=graph_name))


@app.route("/playbook_graph/view/<filename>")
@login_required
def view_playbook_graph(filename):
    graph_dir = os.path.abspath("/var/lib/netpac/graphs")
    graph_path = os.path.abspath(os.path.join(graph_dir, filename + ".svg"))
    
    if not is_safe_path(graph_path, graph_dir):
        logger.warning(f"Path traversal attempt detected: {filename}")
        abort(403)
    
    if not os.path.exists(graph_path):
        abort(404)
    
    with open(graph_path, "r") as f:
        svg_content = f.read()
    
    return render_template("playbook_graph.html", svg=svg_content, filename=filename)


@app.route("/playbook_syntax_check/<path:subpath>", methods=["POST"])
@login_required
def playbook_syntax_check(subpath):
    playbooks_base = os.path.realpath("/var/lib/netpac/playbooks")
    git_base = os.path.realpath("/var/lib/netpac/git")

    if subpath == "git" or subpath.startswith("git/"):
        base_dir = git_base
        rel_subpath = subpath[len("git"):].lstrip("/")
    else:
        base_dir = playbooks_base
        rel_subpath = subpath

    target = os.path.realpath(os.path.join(base_dir, rel_subpath))

    if not is_safe_path(target, base_dir):
        logger.warning(f"Path traversal attempt detected: {subpath}")
        abort(403)

    if not os.path.exists(target):
        abort(404)

    ansible = shutil.which("ansible-playbook") or "/usr/bin/ansible-playbook"

    env = os.environ.copy()
    env['PATH'] = '/usr/bin:/usr/local/bin:' + env.get('PATH', '')

    result = subprocess.run(
        [ansible, '--syntax-check', target],
        capture_output=True, text=True,
        env=env
    )

    if result.returncode == 0:
        flash(f"Syntax check passed — {subpath} is valid", "success")
    else:
        flash(f"Syntax check failed: {result.stderr}", "danger")

    return redirect(url_for("browse_playbooks", subpath=subpath))


@app.route("/run_playbook/<path:subpath>", methods=["POST"])
@login_required
def run_playbook(subpath):
    base_dir = os.path.abspath("/var/lib/netpac/playbooks")
    target_path = os.path.abspath(os.path.join(base_dir, subpath))
    dry_run = request.form.get("dry_run") == "on"

    if not is_safe_path(target_path, base_dir):
        logger.warning(f"Path traversal attempt detected: {subpath}")
        abort(403)

    reap_stale_jobs()

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM history_jobs WHERE script_name = %s AND status = 'running'", (subpath,))
    running = cur.fetchone()[0]
    cur.close()
    conn.close()

    if running > 0:
        flash(f"Playbook '{subpath}' is already running.", "danger")
        return redirect(url_for("history"))

    target_required = request.form.get("targetRequired", "yes")
    target = request.form.get("target", "").strip()

    if target_required == "no":
        target = "localhost"
    elif not target:
        flash("Please provide a target host or group.", "danger")
        return redirect(url_for("browse_playbooks", subpath=subpath))

    secret_1 = request.form.get("secret_1", "").strip()
    secret_2 = request.form.get("secret_2", "").strip()
    secret_3 = request.form.get("secret_3", "").strip()

    extra_vars_raw = request.form.get("extra_vars_raw", "").strip()
    extra_vars = {}
    for line in extra_vars_raw.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if k:
                extra_vars[k] = v
    extra_vars_str = json.dumps(extra_vars) if extra_vars else ""

    variables = json.dumps({"extra_vars": extra_vars})
    secrets_json = json.dumps({"secret_1": secret_1, "secret_2": secret_2, "secret_3": secret_3})

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO history_jobs 
            (script_name, user_id, target, variables, status, started_at, credential, job_type, ansible_dry_run)
            VALUES (%s, %s, %s, %s, 'running', NOW(), %s, 'ansible', %s)
        """, (subpath, current_user.id, target, variables, secrets_json, dry_run))
        conn.commit()
        job_id = cur.lastrowid
    except Exception as e:
        logger.error(f"Failed to create playbook job: {e}")
        conn.rollback()
        return redirect(url_for("browse_playbooks", subpath=""))
    finally:
        cur.close()
        conn.close()

    thread = threading.Thread(
        target=execute_playbook_background,
        args=(job_id, subpath, target, extra_vars_str, secret_1, secret_2, secret_3, dry_run)
    )
    thread.daemon = True
    thread.start()

    flash(f"Playbook '{subpath}' started {'(Dry Run) ' if dry_run else ''}(Job #{job_id})", "success")
    return redirect(url_for("history", mode="ansible"))


# --------------------
#   Playbook Templates
# --------------------
@app.route("/playbook_templates")
@login_required
def playbook_templates():
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT template_id, name, description, playbook_path, target, extra_vars, secret_1, secret_2, secret_3, created_at, created_by FROM playbook_templates ORDER BY name")
        rows = cur.fetchall()
        templates = [dict(zip(['template_id','name','description','playbook_path','target','extra_vars','secret_1','secret_2','secret_3','created_at','created_by'], row)) for row in rows]
    finally:
        cur.close()
        conn.close()

    playbooks_base = os.path.realpath("/var/lib/netpac/playbooks")
    git_base = os.path.realpath("/var/lib/netpac/git")

    playbooks = []
    for root, dirs, files in os.walk(playbooks_base):
        dirs[:] = [d for d in dirs if d != '.git']
        for file in sorted(files):
            if file.endswith('.yml') or file.endswith('.yaml'):
                rel = os.path.relpath(os.path.join(root, file), playbooks_base)
                playbooks.append(rel)

    if os.path.exists(git_base):
        for root, dirs, files in os.walk(git_base):
            dirs[:] = [d for d in dirs if d != '.git']
            for file in sorted(files):
                if file.endswith('.yml') or file.endswith('.yaml'):
                    rel = "git/" + os.path.relpath(os.path.join(root, file), git_base)
                    playbooks.append(rel)

    playbooks = sorted(playbooks)

    secrets = []
    if encryption.is_available():
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("SELECT name, username FROM secrets ORDER BY name")
            secrets = [{'name': r[0], 'username': r[1]} for r in cur.fetchall()]
        finally:
            cur.close()
            conn.close()

    return render_template("playbook_templates.html", templates=templates, playbooks=playbooks, secrets=secrets)


@app.route("/playbook_templates/create", methods=["POST"])
@login_required
def create_playbook_template():
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    playbook_path = request.form.get("playbook_path", "").strip()
    target = request.form.get("target", "").strip()
    extra_vars = request.form.get("extra_vars", "").strip()
    secret_1 = request.form.get("secret_1", "").strip()
    secret_2 = request.form.get("secret_2", "").strip()
    secret_3 = request.form.get("secret_3", "").strip()

    if not name or not playbook_path:
        flash("Name and Playbook are required", "danger")
        return redirect(url_for("playbook_templates"))

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO playbook_templates 
            (name, description, playbook_path, target, extra_vars, secret_1, secret_2, secret_3, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (name, description, playbook_path, target, extra_vars, secret_1, secret_2, secret_3, current_user.id))
        conn.commit()
        flash(f"Template '{name}' created", "success")
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to create template: {e}")
        flash("Failed to create template", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("playbook_templates"))


@app.route("/playbook_templates/edit/<int:template_id>", methods=["POST"])
@login_required
def edit_playbook_template(template_id):
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    playbook_path = request.form.get("playbook_path", "").strip()
    target = request.form.get("target", "").strip()
    extra_vars = request.form.get("extra_vars", "").strip()
    secret_1 = request.form.get("secret_1", "").strip()
    secret_2 = request.form.get("secret_2", "").strip()
    secret_3 = request.form.get("secret_3", "").strip()

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE playbook_templates 
            SET name=%s, description=%s, playbook_path=%s, target=%s, 
                extra_vars=%s, secret_1=%s, secret_2=%s, secret_3=%s
            WHERE template_id=%s
        """, (name, description, playbook_path, target, extra_vars, secret_1, secret_2, secret_3, template_id))
        conn.commit()
        flash(f"Template '{name}' updated", "success")
    except Exception as e:
        conn.rollback()
        flash("Failed to update template", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("playbook_templates"))


@app.route("/playbook_templates/delete/<int:template_id>", methods=["POST"])
@login_required
def delete_playbook_template(template_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM playbook_templates WHERE template_id = %s", (template_id,))
        conn.commit()
        flash("Template deleted", "success")
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to delete template: {e}")
        flash("Failed to delete template", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("playbook_templates"))


@app.route("/playbook_templates/launch/<int:template_id>", methods=["POST"])
@login_required
def launch_playbook_template(template_id):
    dry_run = request.form.get("dry_run") == "on"

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT name, playbook_path, target, extra_vars, secret_1, secret_2, secret_3 FROM playbook_templates WHERE template_id = %s", (template_id,))
        row = cur.fetchone()
    finally:
        cur.close()
        conn.close()

    if not row:
        flash("Template not found", "danger")
        return redirect(url_for("playbook_templates"))

    name, playbook_path, target, extra_vars_raw, secret_1, secret_2, secret_3 = row

    reap_stale_jobs()

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM history_jobs WHERE script_name = %s AND status = 'running'", (playbook_path,))
        running = cur.fetchone()[0]
    finally:
        cur.close()
        conn.close()

    if running > 0:
        flash(f"Playbook '{playbook_path}' is already running.", "danger")
        return redirect(url_for("history", mode="ansible"))

    if not target:
        target = "localhost"

    extra_vars = {}
    if extra_vars_raw:
        for line in extra_vars_raw.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k:
                    extra_vars[k] = v
    extra_vars_str = json.dumps(extra_vars) if extra_vars else ""

    variables = json.dumps({"extra_vars": extra_vars, "template": name})
    secrets_json = json.dumps({"secret_1": secret_1 or "", "secret_2": secret_2 or "", "secret_3": secret_3 or ""})

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO history_jobs 
            (script_name, user_id, target, variables, status, started_at, credential, job_type, ansible_dry_run)
            VALUES (%s, %s, %s, %s, 'running', NOW(), %s, 'ansible', %s)
        """, (playbook_path, current_user.id, target, variables, secrets_json, dry_run))
        conn.commit()
        job_id = cur.lastrowid
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to create template job: {e}")
        flash("Failed to launch template", "danger")
        return redirect(url_for("playbook_templates"))
    finally:
        cur.close()
        conn.close()

    thread = threading.Thread(
        target=execute_playbook_background,
        args=(job_id, playbook_path, target, extra_vars_str, secret_1 or "", secret_2 or "", secret_3 or "", dry_run)
    )
    thread.daemon = True
    thread.start()

    flash(f"Template '{name}' launched {'(Dry Run) ' if dry_run else ''}(Job #{job_id})", "success")
    return redirect(url_for("history", mode="ansible"))


# --------------------
#   Background Playbook execution
# --------------------
def execute_playbook_background(job_id, filename, target, extra_vars_str, secret_1, secret_2, secret_3, dry_run=False):
    exec_logger.info(f"Background executing playbook: {filename}" + (" (DRY RUN)" if dry_run else ""))


    start_time = datetime.now()
    output_script = ""
    status = "completed"
    temp_inventory = None
    env = os.environ.copy()
    env['PATH'] = '/usr/bin:/usr/local/bin:' + env.get('PATH', '')
    env['PYTHONUNBUFFERED'] = '1'
    env['ANSIBLE_FORCE_COLOR'] = '0'
    env['ANSIBLE_STDOUT_CALLBACK'] = 'default'

    ansible = shutil.which("ansible-playbook") or "/usr/bin/ansible-playbook"

    conn = get_db()
    cur = conn.cursor()

    def append_live_output(text):
        try:
            live_conn = get_db()
            live_cur = live_conn.cursor()
            live_cur.execute(
                "UPDATE history_jobs SET output = CONCAT(COALESCE(output, ''), %s) WHERE job_id = %s",
                (text, job_id)
            )
            live_conn.commit()
            live_cur.close()
            live_conn.close()
        except Exception as e:
            exec_logger.error(f"Failed to update live output for job {job_id}: {e}")

    process = None
    output_lines = []

    try:
        if target == "localhost":
            targets = [("localhost",)]
            group_host_map = {}
        elif target:
            resolved = set()
            group_host_map = {}

            for item in target.split(","):
                item = item.strip()
                if not item:
                    continue

                cur.execute("""
                    SELECT DISTINCT h.hostname FROM hosts h
                    JOIN host_group_membership m ON h.host_id = m.host_id
                    JOIN host_groups g ON m.group_id = g.group_id
                    WHERE g.name = %s
                """, (item,))
                group_matches = cur.fetchall()

                if group_matches:
                    hostnames = {row[0] for row in group_matches}
                    resolved.update(hostnames)
                    group_host_map.setdefault(item, set()).update(hostnames)
                else:
                    cur.execute("SELECT DISTINCT hostname FROM hosts WHERE hostname = %s", (item,))
                    host_match = cur.fetchall()
                    if host_match:
                        resolved.update(row[0] for row in host_match)
                    else:
                        raise ValueError(f"Target '{item}' not found in database")

            targets = [(h,) for h in sorted(resolved)]
        else:
            targets = []
            group_host_map = {}

        for num, secret in enumerate([secret_1, secret_2, secret_3], 1):
            if secret:
                cur.execute("SELECT username, encrypted_password FROM secrets WHERE name = %s", (secret,))
                row = cur.fetchone()
                if not row:
                    raise ValueError(f"Secret '{secret}' not found (deleted or renamed?)")
                username, password_enc = row
                decrypted = encryption.decrypt(password_enc)
                env[f'SECRET_{num}_USERNAME'] = username
                env[f'SECRET_{num}_PASSWORD'] = decrypted

        temp_inventory = tempfile.gettempdir() + f"/netpac_inventory_{uuid.uuid4().hex}.ini"
        with open(temp_inventory, "w") as f:
            f.write("[targets]\n")
            for t in targets:
                if t[0] == "localhost":
                    f.write("localhost ansible_connection=local\n")
                else:
                    f.write(t[0] + "\n")

            for group_name, hostnames in group_host_map.items():
                cur.execute("SELECT ansible_vars FROM host_groups WHERE name = %s", (group_name,))
                row = cur.fetchone()
                group_vars_raw = row[0] if row and row[0] else ""

                if group_vars_raw.strip():
                    f.write(f"\n[{group_name}]\n")
                    for h in sorted(hostnames):
                        f.write(h + "\n")

                    f.write(f"\n[{group_name}:vars]\n")
                    for line in group_vars_raw.splitlines():
                        line = line.strip()
                        if "=" in line:
                            f.write(line + "\n")

        playbook_base = os.path.realpath("/var/lib/netpac/playbooks")
        git_base = os.path.realpath("/var/lib/netpac/git")

        if filename == "git" or filename.startswith("git/"):
            base_dir = git_base
            rel_filename = filename[len("git"):].lstrip("/")
        else:
            base_dir = playbook_base
            rel_filename = filename

        playbook_path = os.path.realpath(os.path.join(base_dir, rel_filename))

        if not is_safe_path(playbook_path, base_dir):
            raise ValueError("Invalid playbook path")

        if not os.path.exists(playbook_path):
            raise FileNotFoundError(f"Playbook not found: {filename}")

        args = [ansible, playbook_path, '-i', temp_inventory]

        if extra_vars_str:
            args += ['-e', extra_vars_str]

        if dry_run:
            args += ['--check', '--diff']

        playbook_dir = os.path.dirname(os.path.abspath(playbook_path))

        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env, cwd=playbook_dir,
            start_new_session=True
        )

        try:
            pid_conn = get_db()
            pid_cur = pid_conn.cursor()
            pid_cur.execute("UPDATE history_jobs SET pid = %s WHERE job_id = %s", (process.pid, job_id))
            pid_conn.commit()
            pid_cur.close()
            pid_conn.close()
        except Exception as e:
            exec_logger.error(f"Failed to store PID for job {job_id}: {e}")

        last_update = time.time()
        flushed = 0

        for line in process.stdout:
            output_lines.append(line)
            if time.time() - last_update >= 1:
                append_live_output("".join(output_lines[flushed:]))
                flushed = len(output_lines)
                last_update = time.time()

        process.wait()
        output_script = "".join(output_lines)

        if process.returncode != 0:
            status = "failed"

    except Exception as e:
        status = "failed"
        output_script = f"ERROR: {str(e)}"
        exec_logger.error(f"Unexpected error in playbook execution: {e}")

    finally:
        if temp_inventory and os.path.exists(temp_inventory):
            os.remove(temp_inventory)

        end_time = datetime.now()
        duration = int((end_time - start_time).total_seconds())

        try:
            cur.execute("""
                UPDATE history_jobs 
                SET status = IF(status = 'cancelled', 'cancelled', %s),
                    output = IF(status = 'cancelled', CONCAT(%s, %s), %s),
                    finished_at = NOW(), duration = %s
                WHERE job_id = %s
            """, (status, output_script, JOB_CANCELLED_NOTE, output_script, duration, job_id))
            conn.commit()
        except Exception as e:
            exec_logger.error(f"Failed to update playbook job {job_id}: {e}")
            conn.rollback()
        finally:
            cur.close()
            conn.close()


# --------------------
#   Ansible Collections
# --------------------
ANSIBLE_GALAXY = shutil.which("ansible-galaxy") or "/usr/bin/ansible-galaxy"
COLLECTION_NAME_RE = re.compile(r'^[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+$')

@app.route("/ansible_collections")
@login_required
def ansible_collections():
    collections = []
    system_collections = []

    result = subprocess.run(
        [ANSIBLE_GALAXY, 'collection', 'list', '--format', 'json'],
        capture_output=True, text=True,
        env={**os.environ, 'PATH': '/usr/bin:/usr/local/bin:' + os.environ.get('PATH', '')}
    )

    if result.returncode == 0:
        try:
            raw = json.loads(result.stdout)
            for path, cols in raw.items():
                target_list = collections if '.ansible/collections' in path else system_collections
                for name, info in cols.items():
                    target_list.append({
                        'name': name,
                        'version': info.get('version', 'unknown'),
                        'path': path
                    })
            collections = sorted(collections, key=lambda x: x['name'])
            system_collections = sorted(system_collections, key=lambda x: x['name'])
        except Exception as e:
            logger.error(f"Failed to parse collection list: {e}")

    return render_template(
        "ansible_collections.html",
        collections=collections,
        system_collections=system_collections
    )


@app.route("/ansible_collections/install", methods=["POST"])
@login_required
def ansible_collections_install():
    collection = request.form.get("collection", "").strip()

    if not collection:
        flash("Collection name required", "danger")
        return redirect(url_for("ansible_collections"))

    if not re.match(r'^[a-zA-Z0-9_\.\-]+$', collection):
        flash("Invalid collection name", "danger")
        return redirect(url_for("ansible_collections"))

    result = subprocess.run(
        [ANSIBLE_GALAXY, 'collection', 'install', collection],
        capture_output=True, text=True,
        env={**os.environ, 'PATH': '/usr/bin:/usr/local/bin:' + os.environ.get('PATH', '')}
    )

    if result.returncode == 0:
        flash(f"Collection '{collection}' installed", "success")
    else:
        flash(f"Failed to install '{collection}': {result.stderr}", "danger")

    return redirect(url_for("ansible_collections"))


@app.route("/ansible_collections/uninstall", methods=["POST"])
@login_required
def ansible_collections_uninstall():
    collection = request.form.get("collection", "").strip()

    if not collection:
        flash("Collection name required", "danger")
        return redirect(url_for("ansible_collections"))
    
    if not COLLECTION_NAME_RE.match(collection):
        flash("Invalid collection name (expected namespace.name)", "danger")
        return redirect(url_for("ansible_collections"))

    namespace, _, name = collection.partition('.')
    removed = False

    for pattern in (f'/root/.ansible/collections/ansible_collections/{namespace}/{name}',
                    f'/home/*/.ansible/collections/ansible_collections/{namespace}/{name}'):
        for path in glob.glob(pattern):
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path, ignore_errors=True)
                removed = True

    if removed:
        flash(f"Collection '{collection}' removed", "success")
    else:
        flash(f"Collection '{collection}' not found in user-installed collections (may be a system package)", "danger")

    return redirect(url_for("ansible_collections"))


@app.route("/ansible_collections/update", methods=["POST"])
@login_required
def ansible_collections_update():
    collection = request.form.get("collection", "").strip()

    if not COLLECTION_NAME_RE.match(collection):
        flash("Invalid collection name (expected namespace.name)", "danger")
        return redirect(url_for("ansible_collections"))

    netpac_home = pwd.getpwuid(os.getuid()).pw_dir
    env = {**os.environ,
        'PATH': '/usr/bin:/usr/local/bin:' + os.environ.get('PATH', ''),
        'ANSIBLE_COLLECTIONS_PATH': f'{netpac_home}/.ansible/collections:/usr/lib/python3/dist-packages/ansible_collections'}

    result = subprocess.run(
        [ANSIBLE_GALAXY, 'collection', 'install', collection, '--upgrade'],
        capture_output=True, text=True,
        env=env
    )

    if result.returncode == 0:
        flash(f"Collection '{collection}' updated", "success")
    else:
        flash(f"Failed to update '{collection}': {result.stderr}", "danger")

    return redirect(url_for("ansible_collections"))


@app.route("/ansible_collections/update_all", methods=["POST"])
@login_required
def ansible_collections_update_all():
    result = subprocess.run(
        [ANSIBLE_GALAXY, 'collection', 'list', '--format', 'json'],
        capture_output=True, text=True,
        env={**os.environ, 'PATH': '/usr/bin:/usr/local/bin:' + os.environ.get('PATH', '')}
    )

    if result.returncode == 0:
        try:
            raw = json.loads(result.stdout)
            count = 0
            for path, cols in raw.items():
                if '.ansible/collections' not in path:
                    continue
                for name in cols:
                    subprocess.run(
                        [ANSIBLE_GALAXY, 'collection', 'install', name, '--upgrade'],
                        capture_output=True, text=True,
                        env={**os.environ, 'PATH': '/usr/bin:/usr/local/bin:' + os.environ.get('PATH', '')}
                    )
                    count += 1
            flash(f"Updated {count} collections", "success")
        except Exception as e:
            flash(f"Failed to update collections: {e}", "danger")
    else:
        flash("Failed to list collections", "danger")

    return redirect(url_for("ansible_collections"))


# --------------------
#   History
# --------------------
@app.route("/history")
@login_required
def history():
    reap_stale_jobs()

    page = max(1, request.args.get("page", 1, type=int))
    search = request.args.get("search", "").strip()
    mode = request.args.get("mode", "python").strip()
    per_page = 100
    offset = (page - 1) * per_page

    conn = get_db()
    cur = conn.cursor()

    where_parts = []
    params = []

    if mode in ("python", "ansible"):
        if mode == "python":
            where_parts.append("(job_type IS NULL OR job_type = 'python')")
        else:
            where_parts.append("job_type = %s")
            params.append(mode)

    if search:
        where_parts.append("""(
            CAST(job_id AS CHAR) LIKE %s
            OR script_name LIKE %s
            OR target LIKE %s
            OR status LIKE %s
            OR CAST(started_at AS CHAR) LIKE %s
            OR CAST(duration AS CHAR) LIKE %s
        )""")
        like = f"%{search}%"
        params += [like, like, like, like, like, like]

    where_clause = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

    cur.execute(f"SELECT COUNT(*) FROM history_jobs {where_clause}", params)
    total_jobs = cur.fetchone()[0]

    cur.execute(f"""
        SELECT job_id, script_name, target, status, started_at, finished_at, duration, job_type, ansible_dry_run
        FROM history_jobs 
        {where_clause}
        ORDER BY job_id DESC
        LIMIT %s OFFSET %s
    """, params + [per_page, offset])

    rows = cur.fetchall()

    all_jobs = []
    for row in rows:
        all_jobs.append({
            'job_id': row[0],
            'script_name': row[1],
            'target': row[2],
            'status': row[3],
            'started_at': row[4],
            'finished_at': row[5],
            'duration': row[6],
            'job_type': row[7] if row[7] else 'python',
            'dry_run': bool(row[8])
        })

    cur.close()
    conn.close()

    total_pages = max(1, (total_jobs + per_page - 1) // per_page)

    return render_template(
        "history.html",
        jobs=all_jobs,
        page=page,
        total_pages=total_pages,
        total_jobs=total_jobs,
        search=search,
        mode=mode
    )


@app.route("/history/<int:job_id>")
@login_required
def history_detail(job_id):
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT job_id, script_name, user_id, target, variables, status, 
            output, started_at, finished_at, duration, credential, job_type, ansible_dry_run
        FROM history_jobs 
        WHERE job_id = %s
    """, (job_id,))
    
    row = cur.fetchone()
    
    cur.close()
    conn.close()
    
    if not row:
        abort(404)
    
    if row[10]:
        secrets_json = json.loads(row[10])
    else:
        secrets_json = None

    job = {
        'job_id': row[0],
        'script_name': row[1],
        'user_id': row[2],
        'target': row[3],
        'variables': json.loads(row[4]) if row[4] else None,
        'status': row[5],
        'output': row[6],
        'started_at': row[7],
        'finished_at': row[8],
        'duration': row[9],
        'secrets': secrets_json,
        'job_type': row[11] if len(row) > 11 and row[11] else 'python',
        'dry_run': bool(row[12]) if len(row) > 12 else False
    }
    
    return render_template("history_detail.html", job=job)


@app.route("/history/<int:job_id>/status")
@login_required
def history_job_status(job_id):
    reap_stale_jobs()

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT status, output, finished_at, duration FROM history_jobs WHERE job_id = %s", (job_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return {"error": "not found"}, 404

    return {
        "status": row[0],
        "output": row[1] or "",
        "finished": row[2] is not None,
        "duration": row[3]
    }


@app.route("/history/<int:job_id>/cancel", methods=["POST"])
@login_required
def cancel_job(job_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT status, pid FROM history_jobs WHERE job_id = %s", (job_id,))
        row = cur.fetchone()
        if not row:
            abort(404)

        status, pid = row
        if status != 'running':
            flash(f"Job #{job_id} is not running anymore", "warning")
            return redirect(url_for("history_detail", job_id=job_id))

        if not pid:
            flash(f"Job #{job_id} is still starting — try again in a moment", "warning")
            return redirect(url_for("history_detail", job_id=job_id))

        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            logger.error(f"No permission to cancel job {job_id} (PID {pid})")
            flash(f"No permission to stop process {pid}. Stop it via SSH: sudo kill -TERM -{pid}", "danger")
            return redirect(url_for("history_detail", job_id=job_id))

        cur.execute("""
            UPDATE history_jobs
            SET status = 'cancelled',
                finished_at = NOW(),
                duration = TIMESTAMPDIFF(SECOND, started_at, NOW()),
                output = CONCAT(COALESCE(output, ''), %s)
            WHERE job_id = %s AND status = 'running'
        """, (JOB_CANCELLED_NOTE, job_id))
        conn.commit()

        logger.info(f"Job {job_id} (PID {pid}) cancelled by {current_user.id}")
        flash(f"Job #{job_id} cancelled", "success")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("history_detail", job_id=job_id))


# --------------------
#   Export history output as txt  
# --------------------
@app.route('/export_history_txt/<int:job_id>')
@login_required
def export_history_txt(job_id):
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("SELECT script_name, output FROM history_jobs WHERE job_id = %s", (job_id,))
    row = cur.fetchone()
    
    cur.close()
    conn.close()
    
    if not row:
        abort(404)
    
    script_name, output = row
    
    if not output:
        output = "No output available."
    
    name = secure_filename(script_name)
    safe_name = name.replace(".py", "")
    filename = f"{safe_name}_{job_id}.txt"

    response = make_response(output)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


# ---------------------
#   Schedule
# ---------------------
@app.route("/schedule")
@login_required
def schedule():
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM schedule_jobs ORDER BY created_at DESC")
    jobs = cur.fetchall()

    cur.execute("SELECT name, username FROM secrets ORDER BY name")
    secrets = [{'name': row[0], 'username': row[1]} for row in cur.fetchall()]
    
    cur.close()
    conn.close()

    scripts = []
    base_dir = "/var/lib/netpac/scripts"
    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d != '.git']
        for file in sorted(files):
            if file.endswith('.py'):
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, base_dir)
                scripts.append(relative_path)
    scripts = sorted(scripts)

    playbooks_base = os.path.realpath("/var/lib/netpac/playbooks")
    git_base = os.path.realpath("/var/lib/netpac/git")
    playbooks = []
    for root, dirs, files in os.walk(playbooks_base):
        dirs[:] = [d for d in dirs if d != '.git']
        for file in sorted(files):
            if file.endswith('.yml') or file.endswith('.yaml'):
                rel = os.path.relpath(os.path.join(root, file), playbooks_base)
                playbooks.append(rel)
    if os.path.exists(git_base):
        for root, dirs, files in os.walk(git_base):
            dirs[:] = [d for d in dirs if d != '.git']
            for file in sorted(files):
                if file.endswith('.yml') or file.endswith('.yaml'):
                    rel = "git/" + os.path.relpath(os.path.join(root, file), git_base)
                    playbooks.append(rel)
    playbooks = sorted(playbooks)

    return render_template("schedule.html", jobs=jobs, secrets=secrets, scripts=scripts, playbooks=playbooks)


@app.route("/schedule/add", methods=["POST"])
@login_required
def add_schedule():

    job_type = request.form.get("job_type", "python").strip()
    script_name = request.form.get("script_name", "").strip()
    target = request.form.get("target", "").strip()
    schedule_type = request.form.get("schedule_type", "").strip()
    secret_1 = request.form.get("secret_1", "").strip()
    secret_2 = request.form.get("secret_2", "").strip()
    secret_3 = request.form.get("secret_3", "").strip()

    if job_type == "ansible" and not target:
        target = "localhost"

    if job_type == "ansible":
        extra_vars_raw = request.form.get("extra_vars_raw", "").strip()
        extra_vars = {}
        for line in extra_vars_raw.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k:
                    extra_vars[k] = v
        variables = json.dumps({"extra_vars": extra_vars})
        use_venv = 0
    else:
        var_count = parse_var_count(request.form.get("varCount"))
        vars_dict = {"varCount": var_count}
        for i in range(1, var_count + 1):
            vars_dict[f"variable{i}"] = request.form.get(f"variable{i}", "").strip()
        variables = json.dumps(vars_dict)
        use_venv = 1 if request.form.get("use_venv") == "on" else 0

    secrets_json = json.dumps({
        "secret_1": secret_1,
        "secret_2": secret_2,
        "secret_3": secret_3
    })

    if schedule_type == "hourly":
        schedule = "0 * * * *"
    elif schedule_type == "daily":
        hour = request.form.get("hour", "0")
        minute = request.form.get("minute", "0")
        schedule = f"{minute} {hour} * * *"
    elif schedule_type == "weekly":
        hour = request.form.get("hour", "0")
        minute = request.form.get("minute", "0")
        weekday = request.form.get("weekday", "0")
        schedule = f"{minute} {hour} * * {weekday}"
    elif schedule_type == "custom":
        schedule = request.form.get("schedule", "").strip()
    else:
        flash("Invalid schedule type", "danger")
        return redirect(url_for("schedule"))

    if not script_name or not schedule:
        flash("Script/Playbook and schedule are required", "danger")
        return redirect(url_for("schedule"))

    try:
        if len(schedule.split()) != 5:
            raise ValueError("expected 5 fields")
        CronTrigger(**parse_schedule(schedule))
    except Exception as e:
        flash(f"Invalid schedule '{schedule}': {e}", "danger")
        return redirect(url_for("schedule"))

    conn = get_db()
    cur = conn.cursor()
    try:
        conn.begin()
        cur.execute("""
            INSERT INTO schedule_jobs 
            (script_name, user_id, target, schedule_expression, variables, credential, is_active, created_at, use_venv, job_type)
            VALUES (%s, %s, %s, %s, %s, %s, TRUE, NOW(), %s, %s)
        """, (script_name, current_user.id, target, schedule, variables, secrets_json, use_venv, job_type))
        cron_id = cur.lastrowid

        scheduler.add_job(
            trigger_schedule_job,
            trigger='cron',
            id=str(cron_id),
            replace_existing=True,
            kwargs={
                'job_id': cron_id,
                'script_name': script_name,
                'user_id': current_user.id,
                'target': target,
                'variables': variables,
                'secrets_json': secrets_json,
                'use_venv': bool(use_venv),
                'job_type': job_type
            },
            **parse_schedule(schedule)
        )
        conn.commit()
        flash("Schedule added", "success")

    except Exception as e:
        scheduler_logger.error(f"Error adding schedule: {e}")
        conn.rollback()
        flash("Error adding schedule", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("schedule"))


@app.route("/schedule/toggle/<int:cron_id>", methods=["POST"])
@login_required
def toggle_schedule(cron_id):
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT is_active FROM schedule_jobs WHERE job_id = %s", (cron_id,))
        row = cur.fetchone()

        if not row:
            abort(404)

        new_status = not row[0]
        cur.execute("UPDATE schedule_jobs SET is_active = %s WHERE job_id = %s", (new_status, cron_id))
        conn.commit()

        if new_status:
            cur.execute("SELECT * FROM schedule_jobs WHERE job_id = %s", (cron_id,))
            job = cur.fetchone()
            scheduler.add_job(
                trigger_schedule_job,
                trigger='cron',
                id=str(cron_id),
                replace_existing=True,
                kwargs={
                    'job_id': cron_id,
                    'script_name': job[1],
                    'user_id': job[2],
                    'target': job[3],
                    'variables': job[4],
                    'secrets_json': job[8],
                    'use_venv': bool(job[9]) if job[9] is not None else False,
                    'job_type': job[10] if len(job) > 10 and job[10] else 'python'
                },
                **parse_schedule(job[7])
            )
        else:
            try:
                scheduler.remove_job(str(cron_id))
                scheduler_logger.info(f"Job {cron_id} removed from scheduler")
            except Exception as e:
                scheduler_logger.error(f"Could not remove job {cron_id}: {e}")

        flash("Schedule updated", "success")

    except Exception as e:
        scheduler_logger.error(f"Error toggling schedule: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("schedule"))


@app.route("/schedule/delete/<int:cron_id>", methods=["POST"])
@login_required
def delete_schedule(cron_id):
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("DELETE FROM schedule_jobs WHERE job_id = %s", (cron_id,))
        conn.commit()

        try:
            scheduler.remove_job(str(cron_id))
        except Exception:
            pass

        flash("Schedule deleted", "success")

    except Exception as e:
        scheduler_logger.error(f"Error deleting schedule: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("schedule"))


# ---------------------
#   Settings route
# ---------------------
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    output = None
    active_tab = request.args.get("tab", "user")
    
    log_dir = "/var/log/netpac"
    log_files = []
    
    try:
        if os.path.exists(log_dir):
            for filename in os.listdir(log_dir):
                if filename.endswith('.log'):
                    file_path = os.path.join(log_dir, filename)
                    stat_info = os.stat(file_path)
                    log_files.append({
                        'name': filename,
                        'size': stat_info.st_size,
                        'modified': datetime.fromtimestamp(stat_info.st_mtime)
                    })
            
            log_files.sort(key=lambda x: x['modified'], reverse=True)
    except Exception as e:
        logger.error(f"Error listing logs: {e}")
    
    backup_files = []
    try:
        if os.path.exists(BACKUP_DIR):
            for filename in os.listdir(BACKUP_DIR):
                if filename.endswith('.sql'):
                    file_path = os.path.join(BACKUP_DIR, filename)
                    stat_info = os.stat(file_path)
                    backup_files.append({
                        'name': filename,
                        'size': stat_info.st_size,
                        'modified': datetime.fromtimestamp(stat_info.st_mtime),
                        'type': 'hosts' if 'hosts_backup' in filename else 'full'
                    })
            backup_files.sort(key=lambda x: x['modified'], reverse=True)
    except Exception as e:
        logger.error(f"Error listing backups: {e}")

    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("SELECT method FROM user WHERE name = %s", (current_user.id,))
    row = cur.fetchone()
    user_method = row[0] if row else None

    cur.execute("SELECT name FROM user WHERE name != 'admin' AND method = 'local'")
    users = cur.fetchall()

    cur.close()
    conn.close()
    
    git_config = load_git_config()
    
    radius_config = load_radius_config()

    ssl_info_data = get_ssl_info()

    return render_template("settings.html", output=output, logs=log_files, git_config=git_config, 
                        user_method=user_method, users=users, backups=backup_files, 
                        active_tab=active_tab, radius_config=radius_config, ssl_info=ssl_info_data)


@app.route("/settings/git", methods=["POST"])
@login_required
def save_git_config():
    repo_url     = request.form.get("repo_url", "").strip()
    branch       = request.form.get("branch", "main").strip()
    token_input  = request.form.get("access_token", "").strip()

    if not repo_url:
        flash("The repo URL cannot be empty", "danger")
        return redirect(url_for("settings", tab="git"))

    if not repo_url.startswith("https://"):
        flash("The URL must begin with https://", "danger")
        return redirect(url_for("settings", tab="git"))

    if not re.match(r'^[a-zA-Z0-9_\-/\.]+$', branch):
        flash("Invalid branch name", "danger")
        return redirect(url_for("settings", tab="git"))

    existing = load_git_config()

    if token_input:

        if not encryption.is_available():
            flash("Encryption is not available – The token cannot be saved", "danger")
            return redirect(url_for("settings", tab="git"))
        try:
            token_encrypted = encryption.encrypt(token_input)
        except Exception as e:
            logger.error(f"Error encrypting git token: {e}")
            flash("Error encrypting git token", "danger")
            return redirect(url_for("settings", tab="git"))
    else:

        token_encrypted = existing.get("token_encrypted", "")

    try:
        with open(GIT_CONFIG_FILE, "w") as f:
            json.dump({
                "repo_url":        repo_url,
                "branch":          branch,
                "token_encrypted": token_encrypted
            }, f)
        logger.info(f"Git config saved by {current_user.id}: {repo_url} @ {branch}")
        flash("Git config saved!", "success")
    except Exception as e:
        logger.error(f"Error saving git config: {e}")
        flash("Error saving git config", "danger")

    return redirect(url_for("settings", tab="git"))


@app.route("/settings/logs/<filename>")
@login_required
def view_log(filename):
    log_dir = os.path.realpath("/var/log/netpac")
    safe_filename = secure_filename(filename)

    if not safe_filename.endswith('.log'):
        abort(403)

    file_path = os.path.realpath(os.path.join(log_dir, safe_filename))

    if not is_safe_path(file_path, log_dir):
        logger.warning(f"Path traversal attempt: {filename}")
        abort(403)
    
    if not os.path.exists(file_path):
        abort(404)
    
    try:
        result = subprocess.run(
            ['/usr/bin/tail', '-n', '50', file_path],
            capture_output=True,
            text=True,
            timeout=5
        )
        log_content = result.stdout
        
        if not log_content:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                log_content = ''.join(lines[-50:])
        
        stat_info = os.stat(file_path)
        file_info = {
            'name': safe_filename,
            'size': stat_info.st_size,
            'modified': datetime.fromtimestamp(stat_info.st_mtime),
            'lines': len(log_content.splitlines())
        }
        
        return render_template("log_viewer.html", 
                             log_content=log_content, 
                             file_info=file_info)
        
    except Exception as e:
        logger.error(f"Error reading log {safe_filename}: {e}")
        abort(500)


@app.route("/settings/change_password", methods=["POST"])
@login_required
def change_password():
    current_password = request.form.get("current_password", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    if not current_password or not new_password or not confirm_password:
        flash("All fields are required", "danger")
        return redirect(url_for("settings", tab="user"))

    if new_password != confirm_password:
        flash("New passwords do not match", "danger")
        return redirect(url_for("settings", tab="user"))

    error = validate_password(new_password)
    if error:
        flash(error, "danger")
        return redirect(url_for("settings", tab="user"))

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT password, method FROM user WHERE name = %s", (current_user.id,))
        row = cur.fetchone()

        if not row:
            flash("User not found", "danger")
            return redirect(url_for("settings", tab="user"))

        user_password, method = row

        if method != 'local':
            flash("Password change is only available for local users", "danger")
            return redirect(url_for("settings", tab="user"))

        if not bcrypt.check_password_hash(user_password, current_password):
            flash("Current password is incorrect", "danger")
            return redirect(url_for("settings", tab="user"))

        new_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        cur.execute("UPDATE user SET password = %s WHERE name = %s", (new_hash, current_user.id))
        conn.commit()
        session.pop('default_pw_warning', None)
        flash("Password changed successfully", "success")
        logger.info(f"Password changed for user: {current_user.id}")

    except Exception as e:
        logger.error(f"Error changing password: {e}")
        conn.rollback()
        flash("Error changing password", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("settings", tab="user"))


@app.route("/settings/add_user", methods=["POST"])
@login_required
def add_user():
    if current_user.id != 'admin':
        abort(403)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    method = "local"

    if not username or not password:
        flash("Username and password are required", "danger")
        return redirect(url_for("settings", tab="user"))

    error = validate_password(password)
    if error:
        flash(error, "danger")
        return redirect(url_for("settings", tab="user"))

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT COUNT(*) FROM user WHERE name = %s", (username,))
        if cur.fetchone()[0] > 0:
            flash(f"User '{sanitize_log(username)}' already exists can't be added", "danger")
            return redirect(url_for("settings", tab="user"))

        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        cur.execute(
            "INSERT INTO user (name, password, method) VALUES (%s, %s, %s)",
            (username, hashed, method)
        )
        conn.commit()
        flash(f"User '{sanitize_log(username)}' created successfully", "success")
        logger.info(f"User '{sanitize_log(username)}' created by {current_user.id}")

    except Exception as e:
        logger.error(f"Error creating user: {e}")
        conn.rollback()
        flash("Error creating user", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("settings", tab="user"))


@app.route("/settings/delete_user", methods=["POST"])
@login_required
def delete_user():
    if current_user.id != 'admin':
        abort(403)

    username = request.form.get("username", "").strip()

    if not username or username == 'admin':
        flash("Cannot delete this user", "danger")
        return redirect(url_for("settings", tab="user"))

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("DELETE FROM user WHERE name = %s", (username,))
        conn.commit()
        flash(f"User '{sanitize_log(username)}' deleted successfully", "success")
        logger.info(f"User '{sanitize_log(username)}' deleted by {current_user.id}")

    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        conn.rollback()
        flash("Error deleting user", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("settings", tab="user"))


@app.route("/settings/radius", methods=["POST"])
@login_required
def save_radius_config():
    if current_user.id != 'admin':
        abort(403)

    server_host = request.form.get("server_host", "").strip()
    server_port = request.form.get("server_port", "1812").strip()
    secret = request.form.get("secret", "").strip()
    timeout = request.form.get("timeout", "5").strip()

    if not server_host:
        flash("RADIUS server host is required", "danger")
        return redirect(url_for("settings", tab="radius"))

    try:
        server_port = int(server_port)
        timeout = int(timeout)
    except ValueError:
        flash("Port and timeout must be numbers", "danger")
        return redirect(url_for("settings", tab="radius"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT encrypted_secret FROM radius WHERE id = 1")
    existing = cur.fetchone()

    if secret:
        encrypted_secret = encryption.encrypt(secret)
    elif existing and existing[0]:
        encrypted_secret = existing[0]
    else:
        encrypted_secret = None

    try:
        cur.execute("""
            INSERT INTO radius (id, server, port, encrypted_secret, timeout)
            VALUES (1, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                server = VALUES(server),
                port = VALUES(port),
                encrypted_secret = VALUES(encrypted_secret),
                timeout = VALUES(timeout)
        """, (server_host, server_port, encrypted_secret, timeout))
        conn.commit()
        logger.info(f"RADIUS config updated by {current_user.id}")
        flash("RADIUS configuration saved", "success")
    except Exception as e:
        logger.error(f"Error saving RADIUS config: {e}")
        conn.rollback()
        flash("Error saving RADIUS configuration", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("settings", tab="radius"))


@app.route("/settings/radius/test", methods=["POST"])
@login_required
def test_radius_config():
    if current_user.id != 'admin':
        abort(403)

    test_username = request.form.get("test_username", "").strip()
    test_password = request.form.get("test_password", "")

    if not test_username or not test_password:
        return jsonify({"success": False, "message": "Username and password required"}), 400

    server_host = request.form.get("server_host", "").strip()
    server_port = request.form.get("server_port", "1812").strip()
    secret_input = request.form.get("secret", "").strip()
    timeout = request.form.get("timeout", "5").strip()

    if not server_host:
        return jsonify({"success": False, "message": "Server host is required"}), 400

    try:
        server_port = int(server_port)
        timeout = int(timeout)
    except ValueError:
        return jsonify({"success": False, "message": "Port and timeout must be numbers"}), 400

    if secret_input:
        radius_secret = secret_input
    else:
        radius_secret = get_radius_secret()
        if not radius_secret:
            return jsonify({"success": False, "message": "No secret provided and none saved yet"}), 400

    try:
        srv = Client(
            server=server_host,
            authport=server_port,
            secret=radius_secret.encode(),
            dict=Dictionary(f"{dir_path}/dictionary"),
            timeout=timeout
        )

        req = srv.CreateAuthPacket(
            code=pyrad.packet.AccessRequest,
            User_Name=test_username,
            NAS_Identifier="NetPAC"
        )
        req["User-Password"] = req.PwCrypt(test_password)
        req.add_message_authenticator()
        reply = srv.SendPacket(req)

        if reply.code == pyrad.packet.AccessAccept:
            logger.info(f"RADIUS test successful for user '{sanitize_log(test_username)}' by {current_user.id}")
            return jsonify({"success": True, "message": f"Access-Accept received for '{test_username}'"})
        else:
            return jsonify({"success": False, "message": f"Access-Reject received for '{test_username}'"})

    except Exception as e:
        logger.error(f"RADIUS test failed: Error: {e!r}")
        return jsonify({"success": False, "message": f"Error: {e!r}"}), 500


def get_ssl_info():
    cert_path = os.path.join(SSL_CERT_DIR, "netpac.crt")
    info = {"exists": False}

    if os.path.exists(cert_path):
        try:
            from cryptography.x509 import load_pem_x509_certificate
            with open(cert_path, "rb") as f:
                cert = load_pem_x509_certificate(f.read())

            info = {
                "exists": True,
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": format(cert.serial_number, 'X'),
                "not_valid_after": cert.not_valid_after_utc,
                "is_self_signed": cert.subject == cert.issuer
            }
        except Exception as e:
            logger.error(f"Failed to read SSL cert info: {e}")

    return info


@app.route("/settings/ssl/upload", methods=["POST"])
@login_required
def upload_ssl_cert():
    if current_user.id != 'admin':
        abort(403)

    cert_file = request.files.get('cert_file')
    key_file = request.files.get('key_file')

    if not cert_file or not key_file or cert_file.filename == '' or key_file.filename == '':
        flash("Both certificate and key file are required", "danger")
        return redirect(url_for("settings", tab="ssl"))

    cert_data = cert_file.read()
    key_data = key_file.read()

    try:
        from cryptography.x509 import load_pem_x509_certificate
        from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
        cert = load_pem_x509_certificate(cert_data)
        key = load_pem_private_key(key_data, password=None)
    except Exception as e:
        flash(f"Invalid certificate or key file: {e}", "danger")
        return redirect(url_for("settings", tab="ssl"))

    cert_pub = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    key_pub = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    if cert_pub != key_pub:
        flash("The private key does not belong to this certificate — nothing was changed", "danger")
        return redirect(url_for("settings", tab="ssl"))

    os.makedirs(SSL_CERT_DIR, exist_ok=True)

    cert_path = os.path.join(SSL_CERT_DIR, "netpac.crt")
    key_path = os.path.join(SSL_CERT_DIR, "netpac.key")

    if os.path.exists(cert_path):
        shutil.copy2(cert_path, cert_path + ".bak")
    if os.path.exists(key_path):
        shutil.copy2(key_path, key_path + ".bak")

    try:
        with open(cert_path, "wb") as f:
            f.write(cert_data)
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "wb") as f:
            f.write(key_data)
        os.chmod(key_path, 0o640)

        logger.info(f"SSL certificate updated by {current_user.id}")
        flash("Certificate uploaded successfully. Restart nginx to apply: sudo systemctl reload nginx", "success")

    except Exception as e:
        logger.error(f"SSL upload error: {e}")
        flash(f"Error saving certificate: {str(e)}", "danger")

    return redirect(url_for("settings", tab="ssl"))


# ---------------------
#   Server error route
# ---------------------
@app.errorhandler(404)
def not_found_error(error):
    logger.error(f"404 Error - URL: {request.url} - Method: {request.method} - IP: {get_real_ip()}")
    logger.error(f"Referrer: {request.referrer}")
    logger.error(f"User-Agent: {request.headers.get('User-Agent')}")
    
    return render_template("error.html", 
                         error_code=404, 
                         error_message="Page not found"), 404


@app.errorhandler(Exception)
def handle_error(e):
    error_code = getattr(e, 'code', 500)
    
    logger.error(f"Error {error_code}: {type(e).__name__}: {str(e)}")
    logger.error(f"URL: {request.url}")
    logger.error(f"Method: {request.method}")
    logger.error(f"Traceback:", exc_info=True)
    
    error_messages = {
        400: "Invalid Request",
        403: "Access Denied",
        404: "Page Not Found",
        500: "Internal Server Error"
    }
    
    error_message = error_messages.get(error_code, "An error has occurred")
    
    return render_template("error.html", 
                         error_code=error_code, 
                         error_message=error_message), error_code


# ---------------------
#   Secrets
# ---------------------
def find_secret_usages(cur, secret_name):
    usages = []

    cur.execute("SELECT job_id, script_name, credential FROM schedule_jobs")
    for job_id, script_name, credential in cur.fetchall():
        try:
            names = json.loads(credential).values() if credential else []
        except (ValueError, AttributeError):
            continue
        if secret_name in names:
            usages.append(f"Schedule #{job_id} ({script_name})")

    cur.execute("""
        SELECT name FROM playbook_templates
        WHERE secret_1 = %s OR secret_2 = %s OR secret_3 = %s
        ORDER BY name
    """, (secret_name, secret_name, secret_name))
    usages += [f"Template '{row[0]}'" for row in cur.fetchall()]

    return usages

@app.route("/secrets")
@login_required
def secrets():

    if not encryption.is_available():
        flash("The Secrets feature is not available. ENCRYPTION_KEY is missing or invalid.", "danger")
        return redirect(url_for("dashboard"))
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        sql_query = "SELECT id, name, username, description, created_at FROM secrets ORDER BY created_at DESC"
        cur.execute(sql_query)
        all_secrets = cur.fetchall()
        
        secrets_list = []
        for row in all_secrets:
            secrets_list.append({
                'id': row[0],
                'name': row[1],
                'username': row[2],
                'description': row[3],
                'created_at': row[4]
            })
        
        return render_template("secrets.html", secrets=secrets_list)
        
    except Exception as e:
        logger.error(f"Error loading secrets: {e}")
        flash("Error loading secrets", "danger")
        return redirect(url_for("dashboard"))
    finally:
        cur.close()
        conn.close()


@app.route("/secrets/create", methods=["GET", "POST"])
@login_required
def create_secret():

    if not encryption.is_available():
        flash("The Secrets feature is not available. ENCRYPTION_KEY is missing or invalid.", "danger")
        return redirect(url_for("secrets"))
    
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        description = request.form.get("description", "").strip()
        
        if not name or not username or not password:
            flash("Name, username, and password are required fields!", "danger")
            return redirect(url_for("create_secret"))
        
        conn = get_db()
        cur = conn.cursor()
        
        try:
            encrypted_password = encryption.encrypt(password)
            
            sql_query = "INSERT INTO secrets (name, username, encrypted_password, description) VALUES (%s, %s, %s, %s)"
            cur.execute(sql_query, (name, username, encrypted_password, description))
            conn.commit()
            
            logger.info(f"Secret '{name}' created by {current_user.id}")
            flash(f"Secret '{name}' successfully created!", "success")
            return redirect(url_for("secrets"))

        except pymysql.IntegrityError:
            flash(f"A secret named '{name}' already exists", "danger")
            return redirect(url_for("create_secret"))
        except Exception as e:
            conn.rollback()
            logger.error(f"Error creating secret: {e}")
            flash("Error creating secret", "danger")
            return redirect(url_for("create_secret"))
        finally:
            cur.close()
            conn.close()
    
    return render_template("create_secret.html")


@app.route("/secrets/edit/<int:secret_id>", methods=["GET", "POST"])
@login_required
def edit_secret(secret_id):

    if not encryption.is_available():
        flash("The Secrets feature is not available. ENCRYPTION_KEY is missing or invalid.", "danger")
        return redirect(url_for("secrets"))
    
    conn = get_db()
    cur = conn.cursor()
    
    try:

        sql_query = "SELECT id, name, username, description FROM secrets WHERE id = %s"
        cur.execute(sql_query, (secret_id,))
        row = cur.fetchone()
        
        if not row:
            flash("Secret not found", "danger")
            return redirect(url_for("secrets"))
        
        secret = {
            'id': row[0],
            'name': row[1],
            'username': row[2],
            'description': row[3]
        }
        
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            username = request.form.get("username", "").strip()
            new_password = request.form.get("password", "")
            description = request.form.get("description", "").strip()
            
            if not name or not username:
                flash("Name and username are required fields", "danger")
                return render_template("edit_secret.html", secret=secret)
            
            try:

                if new_password:
                    encrypted_password = encryption.encrypt(new_password)
                    sql_update = """
                        UPDATE secrets 
                        SET name = %s, username = %s, encrypted_password = %s, description = %s
                        WHERE id = %s
                    """
                    cur.execute(sql_update, (name, username, encrypted_password, description, secret_id))
                else:
                    sql_update = """
                        UPDATE secrets 
                        SET name = %s, username = %s, description = %s
                        WHERE id = %s
                    """
                    cur.execute(sql_update, (name, username, description, secret_id))
                
                conn.commit()
                logger.info(f"Secret '{name}' (ID: {secret_id}) updated by {current_user.id}")
                flash(f"Secret '{name}' has been updated", "success")

                if name != secret['name']:
                    usages = find_secret_usages(cur, secret['name'])
                    if usages:
                        flash(f"The old name '{secret['name']}' is still used by: {', '.join(usages)}. "
                              f"These jobs will fail until they are updated to '{name}'.", "warning")

                return redirect(url_for("secrets"))
                
            except pymysql.IntegrityError:
                flash(f"A secret named '{name}' already exists", "danger")
            except Exception as e:
                conn.rollback()
                logger.error(f"Error updating secret {secret_id}: {e}")
                flash("Error updating secret", "danger")
        
        return render_template("edit_secret.html", secret=secret)
        
    except Exception as e:
        logger.error(f"Error loading secret {secret_id}: {e}")
        flash("Error loading secret", "danger")
        return redirect(url_for("secrets"))
    finally:
        cur.close()
        conn.close()


@app.route("/secrets/delete/<int:secret_id>", methods=["POST"])
@login_required
def delete_secret(secret_id):
    
    if not encryption.is_available():
        flash("The Secrets feature is not available. ENCRYPTION_KEY is missing or invalid.", "danger")
        return redirect(url_for("secrets"))
    
    conn = get_db()
    cur = conn.cursor()
    
    try:

        sql_select = "SELECT name FROM secrets WHERE id = %s"
        cur.execute(sql_select, (secret_id,))
        row = cur.fetchone()
        
        if not row:
            flash("Secret not found", "warning")
            return redirect(url_for("secrets"))
        
        secret_name = row[0]

        sql_delete = "DELETE FROM secrets WHERE id = %s"
        cur.execute(sql_delete, (secret_id,))
        conn.commit()
        
        logger.info(f"Secret '{secret_name}' (ID: {secret_id}) deleted by {current_user.id}")
        flash(f"Secret '{secret_name}' was deleted", "success")

        usages = find_secret_usages(cur, secret_name)
        if usages:
            flash(f"The deleted secret '{secret_name}' is still used by: {', '.join(usages)}. "
                  f"These jobs will fail until another secret is selected.", "warning")
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error deleting secret {secret_id}: {e}")
        flash("Error deleting the secret", "danger")
    finally:
        cur.close()
        conn.close()
    
    return redirect(url_for("secrets"))


# --------------------
#   Backup
# --------------------


def run_backup_background(backup_type, filename, output_path, tables):
    mysqldump = shutil.which("mysqldump") or "/usr/bin/mysqldump"

    env = os.environ.copy()
    env['PATH'] = '/usr/bin:/usr/local/bin:' + env.get('PATH', '')

    try:
        with open(output_path, "w") as f:
            result = subprocess.run(
                [mysqldump, f"--defaults-extra-file={DB_CNF_FILE}", "--single-transaction", "--routines", db_database] + tables,
                stdout=f,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300,
                env=env
            )

        if result.returncode == 0:
            logger.info(f"Backup completed: {filename} ({backup_type})")
        else:
            if os.path.exists(output_path):
                os.remove(output_path)
            logger.error(f"Backup failed: {result.stderr}")

    except subprocess.TimeoutExpired:
        if os.path.exists(output_path):
            os.remove(output_path)
        logger.error(f"Backup timed out: {filename}")
    except Exception as e:
        if os.path.exists(output_path):
            os.remove(output_path)
        logger.error(f"Backup error: {e}")


@app.route("/settings/backup", methods=["POST"])
@login_required
def create_backup():
    if current_user.id != 'admin':
        abort(403)

    backup_type = request.form.get("backup_type", "").strip()

    if backup_type not in ("hosts", "full"):
        flash("Invalid backup type", "danger")
        return redirect(url_for("settings", tab="backup"))

    os.makedirs(BACKUP_DIR, exist_ok=True)

    if not os.path.exists(DB_CNF_FILE):
        flash("Database credentials file not found. Backup cannot be created.", "danger")
        logger.error(f"Backup failed: {DB_CNF_FILE} does not exist")
        return redirect(url_for("settings", tab="backup"))

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if backup_type == "hosts":
        filename = f"netpac_hosts_backup_{timestamp}.sql"
        tables = ["hosts", "host_groups", "host_group_membership"]
    else:
        filename = f"netpac_full_backup_{timestamp}.sql"
        tables = []

    output_path = os.path.join(BACKUP_DIR, filename)

    thread = threading.Thread(
        target=run_backup_background,
        args=(backup_type, filename, output_path, tables)
    )
    thread.daemon = True
    thread.start()

    logger.info(f"Backup started by {current_user.id}: {filename} ({backup_type})")
    flash(f"Backup '{filename}' is being created in the background — refresh in a moment to see it in the list", "success")

    return redirect(url_for("settings", tab="backup"))


@app.route("/settings/backup/download/<filename>")
@login_required
def download_backup(filename):
    if current_user.id != 'admin':
        abort(403)

    safe_filename = secure_filename(filename)
    backup_dir = os.path.realpath(BACKUP_DIR)
    file_path = os.path.realpath(os.path.join(backup_dir, safe_filename))

    if not is_safe_path(file_path, backup_dir):
        logger.warning(f"Path traversal attempt on backup download: {filename}")
        abort(403)

    if not os.path.exists(file_path):
        abort(404)

    return send_from_directory(backup_dir, safe_filename, as_attachment=True)


@app.route("/settings/backup/delete", methods=["POST"])
@login_required
def delete_backup():
    if current_user.id != 'admin':
        abort(403)

    filename = request.form.get("filename", "").strip()
    safe_filename = secure_filename(filename)
    backup_dir = os.path.realpath(BACKUP_DIR)
    file_path = os.path.realpath(os.path.join(backup_dir, safe_filename))

    if not is_safe_path(file_path, backup_dir):
        logger.warning(f"Path traversal attempt on backup delete: {filename}")
        abort(403)

    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Backup '{safe_filename}' deleted by {current_user.id}")
            flash(f"Backup '{safe_filename}' deleted", "success")
        else:
            flash("Backup not found", "warning")
    except Exception as e:
        logger.error(f"Error deleting backup: {e}")
        flash("Error deleting backup", "danger")

    return redirect(url_for("settings", tab="backup"))


@app.route("/settings/backup/restore", methods=["POST"])
@login_required
def restore_backup():
    if current_user.id != 'admin':
        abort(403)

    filename = request.form.get("filename", "").strip()
    password = request.form.get("confirm_password", "")
    totp_code = request.form.get("confirm_totp", "").strip()

    safe_filename = secure_filename(filename)
    backup_dir = os.path.realpath(BACKUP_DIR)
    file_path = os.path.realpath(os.path.join(backup_dir, safe_filename))

    if not is_safe_path(file_path, backup_dir):
        logger.warning(f"Path traversal attempt on backup restore: {filename}")
        abort(403)

    if not os.path.exists(file_path):
        flash("Backup file not found", "danger")
        return redirect(url_for("settings", tab="backup"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT password, totp_secret, totp_confirmed, method FROM user WHERE name = %s", (current_user.id,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        flash("User not found", "danger")
        return redirect(url_for("settings", tab="backup"))

    stored_hash, totp_secret, totp_confirmed, method = row

    if method != 'local':
        flash("Restore requires local admin authentication with password + TOTP", "danger")
        return redirect(url_for("settings", tab="backup"))

    if not bcrypt.check_password_hash(stored_hash, password):
        logger.warning(f"Failed restore attempt by {current_user.id}: wrong password")
        flash("Incorrect password", "danger")
        return redirect(url_for("settings", tab="backup"))

    if not totp_secret or not totp_confirmed:
        flash("TOTP is not set up or not confirmed for this account — cannot verify restore", "danger")
        return redirect(url_for("settings", tab="backup"))

    totp = pyotp.TOTP(totp_secret)
    if not totp.verify(totp_code, valid_window=1):
        logger.warning(f"Failed restore attempt by {current_user.id}: wrong TOTP code")
        flash("Incorrect TOTP code", "danger")
        return redirect(url_for("settings", tab="backup"))

    is_hosts_backup = "hosts_backup" in safe_filename
    tables = ["hosts", "host_groups", "host_group_membership"] if is_hosts_backup else None

    safety_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safety_filename = f"netpac_pre_restore_safety_{safety_timestamp}.sql"
    safety_path = os.path.join(BACKUP_DIR, safety_filename)

    mysqldump = shutil.which("mysqldump") or "/usr/bin/mysqldump"
    mysql_bin = shutil.which("mysql") or "/usr/bin/mysql"

    env = os.environ.copy()
    env['PATH'] = '/usr/bin:/usr/local/bin:' + env.get('PATH', '')

    try:
        with open(safety_path, "w") as f:
            safety_args = [mysqldump, f"--defaults-extra-file={DB_CNF_FILE}", "--single-transaction", "--routines", db_database]
            if tables:
                safety_args += tables
            safety_result = subprocess.run(safety_args, stdout=f, stderr=subprocess.PIPE, text=True, timeout=300, env=env)

        if safety_result.returncode != 0:
            if os.path.exists(safety_path):
                os.remove(safety_path)
            logger.error(f"Safety backup failed before restore: {safety_result.stderr}")
            flash("Safety backup failed — restore aborted for safety", "danger")
            return redirect(url_for("settings", tab="backup"))

        logger.info(f"Safety backup created before restore: {safety_filename}")

    except Exception as e:
        logger.error(f"Safety backup error: {e}")
        flash(f"Safety backup error: {str(e)} — restore aborted", "danger")
        return redirect(url_for("settings", tab="backup"))

    def import_sql(path):
        try:
            with open(path, "r") as f:
                result = subprocess.run(
                    [mysql_bin, f"--defaults-extra-file={DB_CNF_FILE}", db_database],
                    stdin=f,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=300,
                    env=env
                )
            return result.returncode == 0, result.stderr.strip()
        except Exception as e:
            return False, str(e)

    ok, error = import_sql(file_path)

    if ok:
        logger.info(f"Restore completed by {current_user.id} from backup: {safe_filename}")
        flash(f"Restore from '{safe_filename}' completed successfully. Please restart NetPAC manually: sudo systemctl restart netpac", "success")
        return redirect(url_for("settings", tab="backup"))

    logger.error(f"Restore from {safe_filename} failed: {error} — rolling back to {safety_filename}")

    rollback_ok, rollback_error = import_sql(safety_path)

    if rollback_ok:
        logger.info(f"Rollback to safety backup {safety_filename} completed")
        flash(f"Restore failed: {error}. The previous state was restored automatically from '{safety_filename}'.", "danger")
    else:
        logger.critical(f"Rollback to safety backup {safety_filename} FAILED: {rollback_error}")
        flash(f"Restore failed: {error}. Automatic rollback also failed: {rollback_error}. "
              f"Restore '{safety_filename}' manually via SSH.", "danger")

    return redirect(url_for("settings", tab="backup"))


# ---------------------
#   Health
# ---------------------
@app.route("/health")
@login_required
def health():
    checks = {}
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        number = cur.fetchone()[0]
        if number == 1:
            status = 'ok'
        else:
            status = 'not ok'

        cur.execute("SELECT VERSION()")
        mysql_version = cur.fetchone()[0]

        cur.close()
        conn.close()

        checks['mariadb'] = {
            'status': status,
            'version': mysql_version
        }

    except Exception as e:
        checks['mariadb'] = {'status': 'error', 'message': str(e)}

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) FROM information_schema.tables WHERE table_schema = %s", (db_database,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        checks['sql-size'] = {'status': 'ok', 'message': f"{row[0]} MB"}
    except Exception as e:
        checks['sql-size'] = {'status': 'error', 'message': str(e)}

    try:
        python_path = shutil.which("python3")

        if python_path:
            result = subprocess.run(
                [python_path, '--version'],
                capture_output=True, text=True
            )
            version = (result.stdout or result.stderr).strip()
            checks['python'] = {
                'status': 'ok',
                'version': version
            }
        else:
            checks['python'] = {
                'status': 'error',
                'message': 'python3 not found in PATH'
            }

    except Exception as e:
        checks['python'] = {'status': 'error', 'message': str(e)}

    try:
        result = subprocess.run(
            ['/usr/bin/systemctl', 'is-active', 'netpac-scheduler.service'],
            capture_output=True, text=True
        )
        scheduler_running = result.stdout.strip() == 'active'

        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM schedule_jobs WHERE is_active = 1")
        schedule_jobs = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM apscheduler_jobs")
        apscheduler_jobs = cur.fetchone()[0]

        active_jobs = f"Active jobs in 'schedule_jobs' table: {schedule_jobs} | Active jobs in 'apscheduler_jobs' table: {apscheduler_jobs}"

        cur.close()
        conn.close()

        checks['scheduler'] = {
            'status': 'ok' if scheduler_running else 'error',
            'jobs': active_jobs
        }
    except Exception as e:
        checks['scheduler'] = {'status': 'error', 'message': str(e)}

    try:
        checks['scripts_dir'] = {
            'status': 'ok' if os.path.exists('/var/lib/netpac/scripts') else 'error'
        }
    except Exception as e:
        checks['scripts_dir'] = {'status': 'error', 'message': str(e)}

    try:
        checks['encryption'] = {
            'status': 'ok' if encryption.is_available() else 'error'
        }
    except Exception as e:
        checks['encryption'] = {'status': 'error', 'message': str(e)}

    try:
        venv_python = os.path.join(dir_path, 'venv', 'bin', 'python3')
        venv_pip = os.path.join(dir_path, 'venv', 'bin', 'pip')
        
        if os.path.exists(venv_python) and os.path.exists(venv_pip):
            result = subprocess.run(
                [venv_pip, 'list', '--format=json'],
                capture_output=True, text=True
            )
            pkg_count = len(json.loads(result.stdout)) if result.returncode == 0 else 0
            checks['venv'] = {
                'status': 'ok',
                'packages': pkg_count
            }
        else:
            checks['venv'] = {
                'status': 'error',
                'message': 'Virtual environment not found'
            }
    except Exception as e:
        checks['venv'] = {'status': 'error', 'message': str(e)}

    try:
        env = {**os.environ, 'PATH': '/usr/bin:/usr/local/bin:' + os.environ.get('PATH', '')}
        result = subprocess.run(
            [ANSIBLE_GALAXY, 'collection', 'list', '--format', 'json'],
            capture_output=True, text=True, env=env
        )
        if result.returncode == 0:
            raw = json.loads(result.stdout)
            count = sum(len(cols) for cols in raw.values())
            checks['ansible_galaxy'] = {
                'status': 'ok',
                'collections': count
            }
        else:
            checks['ansible_galaxy'] = {
                'status': 'error',
                'message': result.stderr.strip()
            }
    except Exception as e:
        checks['ansible_galaxy'] = {'status': 'error', 'message': str(e)}

    overall = 'ok' if all(c['status'] == 'ok' for c in checks.values()) else 'error'
    
    return render_template("health.html", checks=checks, overall=overall)


# ---------------------
#   Default checks
# ---------------------
@app.before_request
def check_default_password():

    if not current_user.is_authenticated or current_user.id != 'admin':
        return
    
    if 'default_pw_warning' in session:
        return 
    
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT password FROM user WHERE name = 'admin'")
        row = cur.fetchone()
        if row and bcrypt.check_password_hash(row[0], DEFAULT_PASSWORD):
            session['default_pw_warning'] = True
        else:
            session['default_pw_warning'] = False
    except Exception:
        session['default_pw_warning'] = False
    finally:
        cur.close()
        conn.close()


@app.before_request
def check_long_running_jobs():
    if request.endpoint in (None, 'static', 'favicon', 'apple_touch_icon'):
        return
    if not current_user.is_authenticated:
        return

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT job_id, script_name, pid, job_type, started_at
        FROM history_jobs
        WHERE status = 'running'
        AND pid IS NOT NULL
        AND started_at < DATE_SUB(NOW(), INTERVAL 3 HOUR)
    """)
    long_running = cur.fetchall()
    cur.close()
    conn.close()

    for job_id, script_name, pid, job_type, started_at in long_running:
        flash_key = f"long_job_warned_{job_id}"
        if session.get(flash_key):
            continue

        if job_type == 'ansible':
            base_dir = os.path.realpath("/var/lib/netpac/playbooks")
        else:
            base_dir = os.path.realpath("/var/lib/netpac/scripts")

        flash(
            Markup(
                "⚠️ Job #{} ({}) has been running for over 3 hours (PID {}). "
                "If this is stuck, cancel it on the <a href=\"{}\">job page</a> "
                "or kill the whole process group via SSH: <code>sudo kill -9 -{}</code>"
            ).format(job_id, script_name, pid, url_for("history_detail", job_id=job_id), pid),
            "warning"
        )
        session[flash_key] = True


# ---------------------
#   Icon check
# ---------------------
@app.route('/apple-touch-icon.png')
@app.route('/apple-touch-icon-precomposed.png')
def apple_touch_icon():
    return send_from_directory(app.static_folder, 'apple-touch-icon.png')


# ---------------------
#   Logout route
# ---------------------
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Logged out", "success")
    return redirect(url_for("login"))