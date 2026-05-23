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


# --------------------
#   Configuration variables
# --------------------
dir_path = os.path.dirname(os.path.realpath(__file__))
DEFAULT_PASSWORD = "admin"


# --------------------
#   Initialize Logger 
# --------------------
logger = logging.getLogger()
file_handler = logging.FileHandler("/var/log/netpac/netpac.log", mode="a", encoding="utf-8")
logger.addHandler(file_handler)
logger.setLevel("INFO")

formatter = logging.Formatter(
        "{asctime} - {levelname} - {message}",
                style="{",
                datefmt="%Y-%m-%d %H:%M",
        )

file_handler.setFormatter(formatter)


# ---------------------------------------
#   Log level adjustment 
# ---------------------------------------
# Flask logs from CLI not in logs file 
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
radius_secret = os.getenv("RADIUS_SECRET")
radius_ip = os.getenv("RADIUS_IP")
radius_nas = os.getenv("RADIUS_NAS")
db_user = os.getenv("DB_USER")
db_pw = os.getenv("DB_PW")
db_ip = os.getenv("DB_IP")
db_database = os.getenv("DB_DATABASE")
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
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.config['SESSION_COOKIE_HTTPONLY'] = True  
app.config['SESSION_COOKIE_SECURE'] = True     
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' 
app.jinja_env.filters['fromjson'] = json.loads
csrf = CSRFProtect(app)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,      
    x_proto=1,    
    x_host=1,     
    x_prefix=1    
)

def get_real_ip():

    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

limiter = Limiter(
    app=app,
    key_func=get_real_ip,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# --------------------
#   Define Radius
# --------------------
srv = Client(server=radius_ip, secret=radius_secret.encode(),
             dict = Dictionary(f"{dir_path}/dictionary"))


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
)


# --------------------
#   Schedule Config
# --------------------
jobstores = {'default': SQLAlchemyJobStore(url=f'mysql+pymysql://{db_user}:{db_pw}@{db_ip}/{db_database}')}

scheduler = BackgroundScheduler(jobstores=jobstores)

def parse_schedule(expression):
    parts = expression.split()
    return {
        'minute': parts[0],
        'hour': parts[1],
        'day': parts[2],
        'month': parts[3],
        'day_of_week': parts[4]
    }

def trigger_schedule_job(script_name, user_id, target, variables, secrets_json):
    conn = get_db()
    cur = conn.cursor()
    vars_dict = json.loads(variables) if variables else {}
    secrets_dict = json.loads(secrets_json) if secrets_json else {}
    
    try:
        cur.execute("SELECT GET_LOCK(%s, 0)", (f"job_{script_name}",))
        lock = cur.fetchone()[0]
        
        if lock != 1:
            #logger.info(f"Job {script_name} skipped - lock not acquired")
            return

        cur.execute("""
            SELECT COUNT(*) FROM history_jobs 
            WHERE script_name = %s 
            AND status = 'running'
            AND started_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)
        """, (script_name,))
        
        if cur.fetchone()[0] > 0:
            logger.info(f"Job {script_name} already running, skipping")
            return

        cur.execute("""
            INSERT INTO history_jobs 
            (script_name, user_id, target, variables, status, started_at, credential)
            VALUES (%s, %s, %s, %s, 'running', NOW(), %s)
        """, (script_name, user_id, target, variables, secrets_json))
        conn.commit()
        job_id = cur.lastrowid
        
    finally:
        cur.execute("SELECT RELEASE_LOCK(%s)", (f"job_{script_name}",))
        cur.close()
        conn.close()

    thread = threading.Thread(
        target=execute_script_background,
        args=(
            job_id, script_name, target,
            vars_dict.get('variable1', ''),
            vars_dict.get('variable2', ''),
            vars_dict.get('variable3', ''),
            vars_dict.get('varCount', '0'),
            secrets_dict.get('secret_1', ''),
            secrets_dict.get('secret_2', ''),
            secrets_dict.get('secret_3', '')
        )
    )

    thread.daemon = True
    thread.start()

def load_jobs_from_db():
    logger.info("Loading jobs from DB...")
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM schedule_jobs WHERE is_active = TRUE")
        jobs = cur.fetchall()
        logger.info(f"Found {len(jobs)} active jobs")
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
                        'script_name': job[1],
                        'user_id': job[2],       
                        'target': job[3],      
                        'variables': job[4],    
                        'secrets_json': job[8]  
                    },
                    **parse_schedule(job[7])
                )
                logger.info(f"Job-ID {job[0]} loaded: {job[1]} with schedule plan {job[7]}")
            except Exception as e:
                logger.error(f"Error loading job {job[0]}: {e}")

    except Exception as e:
        logger.error(f"Error in load_jobs_from_db: {e}")


scheduler.start()
load_jobs_from_db()


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
    return User(user_id)


# --------------------
#   Login route
# --------------------
@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute")
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
            try:
                req = srv.CreateAuthPacket(
                    code=pyrad.packet.AccessRequest,
                    User_Name=username,
                    NAS_Identifier=radius_nas
                )
                
                req["User-Password"] = req.PwCrypt(password)
                reply = srv.SendPacket(req)
                
                if reply.code == pyrad.packet.AccessAccept:
                    conn = get_db()
                    cur = conn.cursor()
                    
                    try:
                        cur.execute("SELECT totp_confirmed FROM user WHERE name = %s", (username,))
                        row = cur.fetchone()

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
def totp_setup():
    if "pre_auth_user" not in session:
        return redirect(url_for("login"))

    username = session["pre_auth_user"]

    if request.method == "POST":
        code = request.form.get("code")
        secret = session.get("totp_secret_temp")

        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            conn = get_db()
            cur = conn.cursor()
            cur.execute("UPDATE user SET totp_secret = %s, totp_confirmed = TRUE WHERE name = %s", (secret, username))
            conn.commit()
            
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
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="NetPAC")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template("totp_setup.html", qr_b64=qr_b64, secret=secret)


# ------------------------
#   TOTP for existing user
# ------------------------
@app.route("/totp/verify", methods=["GET", "POST"])
@limiter.limit("5 per minute")
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
        
        method = row[1] if row else "unknown"
        
        totp = pyotp.TOTP(row[0])
        if totp.verify(code):
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
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


# --------------------
#   Dashboard route
# --------------------
@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db()
    cur = conn.cursor() 

    sql_query_hosts = ("SELECT COUNT(DISTINCT hostname) FROM hosts")
    cur.execute(sql_query_hosts)
    all_hosts = cur.fetchone()[0]

    sql_query_groups = ("SELECT COUNT(DISTINCT host_group) FROM hosts")
    cur.execute(sql_query_groups)
    all_groups = cur.fetchone()[0]

    cur.close()
    conn.close()
    
    with open(f"{dir_path}/static/dashboard.md", "r") as f:
        md_text = f.read()

    html_text = Markup(markdown.markdown(md_text, extensions=["fenced_code"]))    
    return render_template("dashboard.html", md=html_text , all_hosts=all_hosts, all_groups=all_groups)


# --------------------
#   Groups route
# --------------------
@app.route("/groups")
@login_required
def groups():

    conn = get_db()
    cur = conn.cursor() 

    cur.execute("SELECT DISTINCT host_group FROM hosts")
    rows = cur.fetchall()

    groups = set()
    for row in rows:
        for group in row[0].split(","):
            groups.add(group.strip())

    groups = sorted(groups)

    cur.close()
    conn.close()
    
    return render_template("groups.html", groups=groups)


# ------------------------
#   Hosts for Group route
# ------------------------
@app.route("/hosts/<group>")
@login_required
def hosts_by_group(group):
    conn = get_db()
    cur = conn.cursor()

    try:
        sql_query = "SELECT DISTINCT hostname, description FROM hosts WHERE host_group = %s"
        cur.execute(sql_query, (group,))
        all_hosts = cur.fetchall()

        host_groups = {}
        for row in all_hosts:
            sql_query = "SELECT host_group FROM hosts WHERE hostname = %s"
            cur.execute(sql_query, (row[0],))

            groups = []
            for r in cur.fetchall():
                groups.append(r[0])
            
            host_groups[row[0]] = ",".join(groups)

    except Exception as e:
        logger.error(f"Exception on hosts_by_group: {type(e).__name__}: {e}")
        all_hosts = []
        host_groups = {}
    finally:
        cur.close()
        conn.close()

    return render_template("hosts.html", hosts=all_hosts, host_groups=host_groups)


# --------------------
#   Hosts route
# --------------------
@app.route("/hosts")
@login_required
def hosts():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT DISTINCT hostname, description FROM hosts")
    all_hosts = cur.fetchall()

    host_groups = {}
    for row in all_hosts:
        sql_cmd = "SELECT host_group FROM hosts WHERE hostname = %s"
        cur.execute(sql_cmd, (row[0],))
        groups = [r[0] for r in cur.fetchall()]
        host_groups[row[0]] = ",".join(groups)

    cur.close()
    conn.close()

    return render_template("hosts.html", hosts=all_hosts, host_groups=host_groups)


# -----------------------
#   Add host to DB route
# -----------------------
@app.route("/hosts", methods=["POST"])
@login_required
def add_host():
    hostname = request.form.get("Hostname", "").strip()
    group = request.form.get("Group", "").strip()
    description = request.form.get("Description", "").strip()
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        sql_check = "SELECT COUNT(*) FROM hosts WHERE hostname = %s"
        cur.execute(sql_check, (hostname,))
        if cur.fetchone()[0] > 0:
            return redirect(url_for("hosts"))

        groups = [g.strip() for g in group.split(",")]
        
        for g in groups:
            if g:
                cur.execute(
                    "INSERT INTO hosts (hostname, host_group, description) VALUES (%s, %s, %s)",
                    (hostname, g, description)
                )
        
        conn.commit()
        logger.info(f"Host {hostname} with Groups: {groups} and description {description} successfully added")
        
    except pymysql.IntegrityError as e:
        logger.error(f"IntegrityError on /hosts [POST]: {e}")
    except Exception as e:
        logger.error(f"Exception on /hosts [POST]: {type(e).__name__}: {e}")
    finally:
        cur.close()
        conn.close()
    
    return redirect(url_for("hosts"))


# --------------------------
#   Update host to DB route
# --------------------------
@app.route("/update_host", methods=["POST"])
@login_required
def update_host():
    hostname = request.form.get("Hostname", "").strip()
    group = request.form.get("Group", "").strip()
    description = request.form.get("Description", "").strip()
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute("DELETE FROM hosts WHERE hostname = %s", (hostname,))
        
        groups = [g.strip() for g in group.split(",")]
        for g in groups:
            if g:
                cur.execute(
                    "INSERT INTO hosts (hostname, host_group, description) VALUES (%s, %s, %s)",
                    (hostname, g, description)
                )
        
        conn.commit()
        logger.info(f"Host {hostname} updated with groups {groups}")
        
    except Exception as e:
        logger.error(f"Exception on update_host: {type(e).__name__}: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()
    
    return redirect(url_for("hosts"))


# --------------------------
#   Delete host to DB route
# --------------------------
@app.route("/hosts/delete", methods=["POST"])
@login_required
def delete_host():
    hostname = request.form.get("hostname", "").strip()
    
    if not hostname:
        return redirect(url_for("hosts"))
    conn = get_db()
    cur = conn.cursor()
    
    try:

        sql_check = "SELECT COUNT(*) FROM hosts WHERE hostname = %s"
        cur.execute(sql_check, (hostname,))
        if cur.fetchone()[0] == 0:
            return redirect(url_for("hosts"))
        

        sql_query = "DELETE FROM hosts WHERE hostname = %s"
        cur.execute(sql_query, (hostname,))
        conn.commit()
        logger.info(f"Host {hostname} successfully deleted")
        
    except Exception as e:
        logger.error(f"Error deleting host {hostname}: {e}")
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


def build_authenticated_url(repo_url: str, token: str) -> str:
    if not token:
        return repo_url
    if repo_url.startswith("https://"):
        return repo_url.replace("https://", f"https://oauth2:{token}@", 1)
    return repo_url


# --------------------
#   Scripts route
# --------------------
@app.route("/scripts")
@login_required
def scripts():
    base_dir = "/var/lib/netpac/scripts"
    git_config = load_git_config()
    entries = []
    for name in sorted(os.listdir(base_dir)):
        full = os.path.join(base_dir, name)
        entries.append({
            "name": name,
            "is_dir": os.path.isdir(full),
            "path": name
        })

    all_scripts = []
    for root, dirs, files in os.walk(base_dir):

        dirs[:] = [d for d in dirs if d != '.git']
        
        for file in sorted(files):
            full_path = os.path.join(root, file)
            relative_path = os.path.relpath(full_path, base_dir)
            all_scripts.append({
                "name": file,
                "path": relative_path,
                "is_dir": False
            })
        all_scripts = sorted(all_scripts, key=lambda x: x['path'])

    return render_template("scripts.html", entries=entries, git_config=git_config, current_path="", all_scripts=all_scripts)


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
    scripts_dir = "/var/lib/netpac/scripts/git"

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

    auth_url = build_authenticated_url(repo_url, token)

    try:
        is_git_repo = os.path.isdir(os.path.join(scripts_dir, ".git"))

        if is_git_repo:
            subprocess.run(
                ["/usr/bin/git", "remote", "set-url", "origin", auth_url],
                capture_output=True, text=True, timeout=10,
                cwd=scripts_dir
            )
            result = subprocess.run(
                ["/usr/bin/git", "pull", "origin", branch],
                capture_output=True, text=True, timeout=60,
                cwd=scripts_dir
            )
        else:
            result = subprocess.run(
                ["/usr/bin/git", "clone", "--branch", branch, auth_url, scripts_dir],
                capture_output=True, text=True, timeout=120
            )

        if result.returncode == 0:
            logger.info(f"Git sync successful by {current_user.id}: {repo_url} @ {branch}")
            flash("Git sync successful", "success")
        else:
            safe_stderr = result.stderr.replace(token, "***") if token else result.stderr
            logger.error(f"Git sync failed for {current_user.id}: {safe_stderr}")
            flash(f"Sync failed: {safe_stderr.strip()}", "danger")

    except subprocess.TimeoutExpired:
        flash("Timeout of 60 seconds exceeded", "danger")
    except Exception as e:
        safe_err = str(e).replace(token, "***") if token else str(e)
        logger.error(f"Git sync error: {safe_err}")
        flash(f"Error sync: {safe_err}", "danger")

    return redirect(url_for("scripts"))


# -----------------------------
#   View selected script route
# -----------------------------
@app.route("/scripts/", defaults={"subpath": ""})
@app.route("/scripts/<path:subpath>")
@login_required
def view_script(subpath):
    base_dir = os.path.abspath("/var/lib/netpac/scripts")
    
    target = os.path.abspath(os.path.join(base_dir, subpath))
    
    if not target.startswith(base_dir):
        logger.warning(f"Path traversal attempt detected: {subpath}")
        abort(403)
    
    if not os.path.exists(target):
        abort(404)
    
    if os.path.isdir(target):
        entries = []
        for name in sorted(os.listdir(target)):
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


# ---------------------
#   Update script route
# ---------------------
@app.route("/scripts/<filename>/update", methods=["POST"])
@login_required
def update_script(filename):
    safe_filename = secure_filename(filename)
    
    script_path = os.path.join("/var/lib/netpac/scripts", safe_filename)
    
    if not os.path.abspath(script_path).startswith(os.path.abspath("/var/lib/netpac/scripts")):
        logger.warning(f"Path traversal attempt detected: {filename}")
        abort(403)
    
    if not os.path.exists(script_path):
        flash("Script not found!", "danger")
        return redirect(url_for("scripts"))
    
    new_content = request.form.get("content", "")
    
    if not new_content:
        flash("Script content cannot be empty!", "danger")
        return redirect(url_for("view_script", filename=safe_filename))
    
    try:

        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        logger.info(f"Script '{safe_filename}' updated by {current_user.id}")
        flash(f"Script '{safe_filename}' successfully updated!", "success")
        
    except Exception as e:
        logger.error(f"Error updating script {safe_filename}: {e}")
        flash("Error updating script!", "danger")
    
    return redirect(url_for('view_script', filename=safe_filename))


# --------------------
#   Run script route
# --------------------
@app.route("/run_scripts/<path:subpath>", methods=["POST"])
@login_required
def run_script(subpath):
    base_dir = os.path.abspath("/var/lib/netpac/scripts")
    target_path = os.path.abspath(os.path.join(base_dir, subpath))
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM history_jobs WHERE script_name = %s AND status = 'running'", (subpath,))
    running = cur.fetchone()[0]
    cur.close()
    conn.close()

    if running > 0:
        flash(f"Script '{subpath}' is already running. Please wait for it to finish.", "danger")
        return redirect(url_for("history"))
    
    if not target_path.startswith(base_dir):
        abort(403)
    
    safe_filename = subpath
    
    target = request.form.get("target", "").strip()
    secret_1 = request.form.get("secret_1", "").strip()
    secret_2 = request.form.get("secret_2", "").strip()
    secret_3 = request.form.get("secret_3", "").strip()
    var_1 = request.form.get("variable1", "").strip()
    var_2 = request.form.get("variable2", "").strip()
    var_3 = request.form.get("variable3", "").strip()
    var = request.form.get("varCount", "0")

    variables = {
        "varCount": var,
        "variable1": var_1,
        "variable2": var_2,
        "variable3": var_3
    }

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
            (script_name, user_id, target, variables, status, started_at, credential) 
            VALUES (%s, %s, %s, %s, 'running', NOW(), %s)
        """, (safe_filename, current_user.id, target, json.dumps(variables), json.dumps(secrets_json)))
        
        conn.commit()
        job_id = cur.lastrowid
        
    except Exception as e:
        logger.error(f"Failed to create job: {e}")
        conn.rollback()
        return redirect(url_for("scripts"))
    finally:
        cur.close()
        conn.close()

    thread = threading.Thread(
        target=execute_script_background,
        args=(job_id, safe_filename, target, var_1, var_2, var_3, var, secret_1, secret_2, secret_3)
    )
    thread.daemon = True
    thread.start()

    flash(f"Script '{safe_filename}' started (Job #{job_id})", "success")
    return redirect(url_for("history"))


# --------------------
#   Background execution
# --------------------
def execute_script_background(job_id, filename, target, var_1, var_2, var_3, var_count, secret_1, secret_2, secret_3):
    logger.info(f"Background executing: {filename}")
    
    start_time = datetime.now()
    output_script = ""
    status = "completed"
    temp_hostfile = None
    env = os.environ.copy()
    
    python = shutil.which("python3") or "/usr/bin/python3"

    conn = get_db()
    cur = conn.cursor()
    
    try:

        if target:
            sql_query = "SELECT DISTINCT hostname FROM hosts WHERE host_group = %s"
            cur.execute(sql_query, (target,))
            targets = cur.fetchall()
            
            if not targets:
                sql_query = "SELECT DISTINCT hostname FROM hosts WHERE hostname = %s"
                cur.execute(sql_query, (target,))
                targets = cur.fetchall()
            
            if not targets:
                raise ValueError(f"Target {target} not found in database")
            
        else:
            targets = []
        
        for num, secret in enumerate([secret_1, secret_2, secret_3], 1):
            if secret:
                cur.execute("SELECT username, encrypted_password FROM secrets WHERE name = %s", (secret,))
                row = cur.fetchone()

                if row:
                    username, password_enc = row
                    decrypted = encryption.decrypt(password_enc)
                    env[f'SECRET_{num}_USERNAME'] = username
                    env[f'SECRET_{num}_PASSWORD'] = decrypted

        temp_hostfile = tempfile.gettempdir() + f"/netpac_hosts_{uuid.uuid4().hex}.txt"
        
        with open(temp_hostfile, "w") as f:
            for t in targets:
                f.write(t[0] + "\n")
        
        script_path = os.path.join("/var/lib/netpac/scripts", filename)
        if not os.path.abspath(script_path).startswith(os.path.abspath("/var/lib/netpac/scripts")):
            raise ValueError("Invalid script path")
        
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Script not found: {filename}")
        

        env['NETPAC_HOSTFILE'] = temp_hostfile
        
        if var_count == "0":
            result = subprocess.run(
                [python, script_path],
                capture_output=True, text=True, check=True,
                timeout=300, env=env
            )
        elif var_count == "1":
            result = subprocess.run(
                [python, script_path, var_1],
                capture_output=True, text=True, check=True,
                timeout=300, env=env
            )
        elif var_count == "2":
            result = subprocess.run(
                [python, script_path, var_1, var_2],
                capture_output=True, text=True, check=True,
                timeout=300, env=env
            )
        elif var_count == "3":
            result = subprocess.run(
                [python, script_path, var_1, var_2, var_3],
                capture_output=True, text=True, check=True,
                timeout=300, env=env
            )
        else:
            raise ValueError("Invalid variable count")
        
        output_script = result.stdout
        
    except subprocess.TimeoutExpired:
        status = "timeout"
        output_script = "ERROR: Script execution timed out (300s)"
        logger.error(f"Script timeout: {filename}")
        
    except subprocess.CalledProcessError as e:
        status = "failed"
        output_script = f"ERROR: Script execution failed\n{e.stderr}"
        logger.error(f"Script error: {filename}")
        
    except Exception as e:
        status = "failed"
        output_script = f"ERROR: {str(e)}"
        logger.error(f"Unexpected error in background script: {e}")
        
    finally:

        if temp_hostfile and os.path.exists(temp_hostfile):
            os.remove(temp_hostfile)
        

        end_time = datetime.now()
        duration = int((end_time - start_time).total_seconds())
        
        try:
            cur.execute("""
                UPDATE history_jobs 
                SET status = %s, output = %s, finished_at = NOW(), duration = %s
                WHERE job_id = %s
            """, (status, output_script, duration, job_id))
            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Failed to update job {job_id}: {e}")
            conn.rollback()
        finally:
            cur.close()
            conn.close()


# --------------------
#   History Dashboard
# --------------------
@app.route("/history")
@login_required
def history():
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT job_id, script_name, target, status, started_at, finished_at, duration
        FROM history_jobs 
        ORDER BY job_id DESC
    """)
    
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
            'duration': row[6]
        })
    
    cur.close()
    conn.close()
    
    return render_template("history.html", jobs=all_jobs)


# --------------------
#   History Details
# --------------------
@app.route("/history/<int:job_id>")
@login_required
def history_detail(job_id):
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT job_id, script_name, user_id, target, variables, status, 
               output, started_at, finished_at, duration, credential
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
        'secrets': secrets_json
    }
    
    return render_template("history_detail.html", job=job)


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
    response.headers["Content-Type"] = "text/plain"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


# ---------------------
#   Schedule route
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
        for file in sorted(files):
            if file.endswith('.py'):
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, base_dir)
                scripts.append(relative_path)
    
    scripts = sorted(scripts)

    return render_template("schedule.html", jobs=jobs, secrets=secrets, scripts=scripts)


# ---------------------
#   Add schedule
# ---------------------
@app.route("/schedule/add", methods=["POST"])
@login_required
def add_schedule():

    script_name = request.form.get("script_name", "").strip()
    target = request.form.get("target", "").strip()
    schedule_type = request.form.get("schedule_type", "").strip()
    secret_1 = request.form.get("secret_1", "").strip()
    secret_2 = request.form.get("secret_2", "").strip()
    secret_3 = request.form.get("secret_3", "").strip()
    var_count = request.form.get("varCount", "0")
    var_1 = request.form.get("variable1", "")
    var_2 = request.form.get("variable2", "")
    var_3 = request.form.get("variable3", "")

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
        flash("Script and schedule are required", "danger")
        return redirect(url_for("schedule"))

    conn = get_db()
    cur = conn.cursor()

    try:

        variables = json.dumps({
            "varCount": var_count,
            "variable1": var_1,
            "variable2": var_2,
            "variable3": var_3
        })

        cur.execute("""
            INSERT INTO schedule_jobs 
            (script_name, user_id, target, schedule_expression, variables, credential, is_active, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, TRUE, NOW())
        """, (script_name, current_user.id, target, schedule, variables, secrets_json))
        conn.commit()
        cron_id = cur.lastrowid

        scheduler.add_job(
            trigger_schedule_job,
            trigger='cron',
            id=str(cron_id),
            replace_existing=True,
            kwargs={
                'script_name': script_name,
                'user_id': current_user.id,
                'target': target,
                'variables': variables,
                'secrets_json': secrets_json
            },
            **parse_schedule(schedule)
        )
        flash("Schedule added", "success")

    except Exception as e:
        logger.error(f"Error adding schedule: {e}")
        conn.rollback()
        flash("Error adding schedule", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("schedule"))


# --------------------------------
#   Schedule activate/deactivate
# --------------------------------
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
                    'script_name': job[1],
                    'user_id': job[2],
                    'target': job[3],
                    'variables': job[4],
                    'secrets_json': job[8] 
                },
                **parse_schedule(job[7])
            )
        else:
            try:
                scheduler.remove_job(str(cron_id))
                logger.info(f"Job {cron_id} removed from scheduler")
            except Exception as e:
                logger.error(f"Could not remove job {cron_id}: {e}")

        flash("Schedule updated", "success")

    except Exception as e:
        logger.error(f"Error toggling schedule: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("schedule"))


# ---------------------
#   Schedule delete
# ---------------------
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
        logger.error(f"Error deleting schedule: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("schedule"))


# ---------------------
#   About route
# ---------------------
@app.route("/about/version")
@login_required
def get_versions():
    
    conn = get_db()
    cur = conn.cursor()
    
    try:

        cur.execute("SELECT VERSION()")
        mysql_version = cur.fetchone()[0]
        
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        
        return {
            "python": python_version,
            "mysql": mysql_version
        }
    except Exception as e:
        logger.error(f"Error fetching versions: {e}")
        return {"python": "Error", "mysql": "Error"}
    finally:
        cur.close()
        conn.close()


# ---------------------
#   Settings route
# ---------------------
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    output = None
    
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
    
    return render_template("settings.html", output=output, logs=log_files, git_config=git_config, user_method=user_method, users=users)


# ---------------------
#   Settings Git
# ---------------------
@app.route("/settings/git", methods=["POST"])
@login_required
def save_git_config():
    repo_url     = request.form.get("repo_url", "").strip()
    branch       = request.form.get("branch", "main").strip()
    token_input  = request.form.get("access_token", "").strip()

    if not repo_url:
        flash("The repo URL cannot be empty", "danger")
        return redirect(url_for("settings"))

    if not repo_url.startswith("https://"):
        flash("The URL must begin with https://", "danger")
        return redirect(url_for("settings"))

    if not re.match(r'^[a-zA-Z0-9_\-/\.]+$', branch):
        flash("Invalid branch name", "danger")
        return redirect(url_for("settings"))

    existing = load_git_config()

    if token_input:

        if not encryption.is_available():
            flash("Encryption is not available – The token cannot be saved", "danger")
            return redirect(url_for("settings"))
        try:
            token_encrypted = encryption.encrypt(token_input)
        except Exception as e:
            logger.error(f"Error encrypting git token: {e}")
            flash("Error encrypting git token", "danger")
            return redirect(url_for("settings"))
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

    return redirect(url_for("settings"))


# ---------------------
#   Settings logs route
# ---------------------
@app.route("/settings/logs/<filename>")
@login_required
def view_log(filename):
    log_dir = "/var/log/netpac"
    safe_filename = secure_filename(filename)
    
    if not safe_filename.endswith('.log'):
        abort(403)
    
    file_path = os.path.join(log_dir, safe_filename)
    
    if not os.path.abspath(file_path).startswith(os.path.abspath(log_dir)):
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


# ---------------------
#   Change password
# ---------------------
@app.route("/settings/change_password", methods=["POST"])
@login_required
def change_password():
    current_password = request.form.get("current_password", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    if not current_password or not new_password or not confirm_password:
        flash("All fields are required", "danger")
        return redirect(url_for("settings"))

    if new_password != confirm_password:
        flash("New passwords do not match", "danger")
        return redirect(url_for("settings"))

    error = validate_password(new_password)
    if error:
        flash(error, "danger")
        return redirect(url_for("settings"))

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT password, method FROM user WHERE name = %s", (current_user.id,))
        row = cur.fetchone()

        if not row:
            flash("User not found", "danger")
            return redirect(url_for("settings"))

        user_password, method = row

        if method != 'local':
            flash("Password change is only available for local users", "danger")
            return redirect(url_for("settings"))

        if not bcrypt.check_password_hash(user_password, current_password):
            flash("Current password is incorrect", "danger")
            return redirect(url_for("settings"))

        new_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        cur.execute("UPDATE user SET password = %s WHERE name = %s", (new_hash, current_user.id))
        conn.commit()
        session.pop('pw_checked', None)
        flash("Password changed successfully", "success")
        logger.info(f"Password changed for user: {current_user.id}")

    except Exception as e:
        logger.error(f"Error changing password: {e}")
        conn.rollback()
        flash("Error changing password", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("settings"))


# ---------------------
#   Add local user
# ---------------------
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
        return redirect(url_for("settings"))

    error = validate_password(password)
    if error:
        flash(error, "danger")
        return redirect(url_for("settings"))

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT COUNT(*) FROM user WHERE name = %s", (username,))
        if cur.fetchone()[0] > 0:
            flash(f"User '{sanitize_log(username)}' already exists can't be added", "danger")
            return redirect(url_for("settings"))

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

    return redirect(url_for("settings"))


# ---------------------
#   Delete local user
# ---------------------
@app.route("/settings/delete_user", methods=["POST"])
@login_required
def delete_user():
    if current_user.id != 'admin':
        abort(403)

    username = request.form.get("username", "").strip()

    if not username or username == 'admin':
        flash("Cannot delete this user", "danger")
        return redirect(url_for("settings"))

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

    return redirect(url_for("settings"))


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
#   Secrets route
# ---------------------
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


# ---------------------
#   Create Secret route
# ---------------------
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
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error creating secret: {e}")
            flash(f"Error creating secret", "danger")
            return redirect(url_for("create_secret"))
        finally:
            cur.close()
            conn.close()
    
    return render_template("create_secret.html")


# ---------------------
#   Edit Secret route
# ---------------------
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
                return redirect(url_for("secrets"))
                
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


# ---------------------
#   Delete Secret route
# ---------------------
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
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error deleting secret {secret_id}: {e}")
        flash("Error deleting the secret", "danger")
    finally:
        cur.close()
        conn.close()
    
    return redirect(url_for("secrets"))


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
        cur.close()
        conn.close()

        checks['mariadb'] = {'status': 'ok'}
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
        checks['scheduler'] = {
            'status': 'ok' if scheduler.running else 'error',
            'jobs': len(scheduler.get_jobs())
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

    overall = 'ok' if all(c['status'] == 'ok' for c in checks.values()) else 'error'
    
    return render_template("health.html", checks=checks, overall=overall)


# ---------------------
#   Default password check
# ---------------------
@app.before_request
def check_default_password():
    if not current_user.is_authenticated:
        return
    
    if current_user.id != 'admin':
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


# ---------------------
#   Logout route
# ---------------------
@app.route("/logout")
@login_required
def logout():

    session.pop('_flashes', None)
    
    logout_user()
    flash("Logged out", "success")
    return redirect(url_for("login"))