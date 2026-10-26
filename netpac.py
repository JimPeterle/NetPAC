# --------------------
#   Import library
# --------------------
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, send_from_directory
from flask import has_request_context
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from pyrad.client import Client, Timeout as RadiusTimeout
from pyrad.dictionary import Dictionary
import pyrad.packet
import pymysql
import os
import subprocess
from dotenv import dotenv_values
import markdown
from markupsafe import Markup
from flask_bcrypt import Bcrypt
import logging
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from flask_limiter import Limiter
from flask import abort
from flask_wtf.csrf import CSRFProtect
import tempfile
import uuid
from werkzeug.middleware.proxy_fix import ProxyFix
import re
import threading
import json
import csv
import hashlib
import hmac
import traceback
from cryptography.fernet import Fernet
import base64
import inspect
from datetime import date, datetime, timedelta
import pyotp
import qrcode
import io
import shutil
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.triggers.cron import CronTrigger
import glob
import pwd
import signal
import time
from flask import jsonify
import urllib
import urllib.parse
import urllib.request
import urllib.error
import smtplib
import ssl
from email.message import EmailMessage
from netpac_migrations import run_migrations, MigrationError


# --------------------
#   Configuration variables
# --------------------
dir_path = os.path.dirname(os.path.realpath(__file__))
APP_VERSION = "6.0.0"
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
    """Removes line breaks from a value so it can't forge extra log lines."""

    return value.replace('\n', ' ').replace('\r', ' ').strip()


# -------------------------------------------------
#   Filter for removce traceback logs from logfile
# -------------------------------------------------
class TracebackInfoFilter(logging.Filter):
    """Logging filter that keeps tracebacks out of the log file."""

    def __init__(self, clear=True):
        """Sets whether tracebacks are hidden (True) or restored (False)."""

        self.clear = clear
    def filter(self, record):
        """Hides or restores the traceback of a log record."""

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
secret_config = dotenv_values(f"{dir_path}/secret.env")


# -----------------------------------------
#   Encryption Key Management (Used to encrypt passwords in the database)
# -----------------------------------------
def ensure_encryption_key():
    """Returns the ENCRYPTION_KEY from secret.env if it is a valid Fernet key, else None."""

    existing_key = secret_config.get("ENCRYPTION_KEY")
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
    """Encrypts and decrypts stored secrets with the Fernet key."""

    def __init__(self, key):
        """Initialises the cipher; encryption is disabled if the key is missing or invalid."""

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
        """Returns True if encryption can be used."""

        return self.cipher is not None
    
    def encrypt(self, password: str) -> str:
        """Encrypts a plain text value."""

        if not self.is_available():
            raise ValueError("Encryption not available - ENCRYPTION_KEY is missing or invalid")
        try:
            return self.cipher.encrypt(password.encode()).decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt(self, encrypted_password: str) -> str:
        """Decrypts a value encrypted with encrypt()."""

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


# --------------------
#   TOTP secret storage
# --------------------
TOTP_PLAIN_RE = re.compile(r'^[A-Z2-7]{16,64}=*$')

def encrypt_totp_secret(secret):
    """Encrypts a TOTP secret for storage (plain text if no key is configured)."""

    if encryption.is_available():
        return encryption.encrypt(secret)
    logger.warning("ENCRYPTION_KEY missing — TOTP secret is stored unencrypted")
    return secret


def decrypt_totp_secret(stored):
    """Returns (secret, needs_reencrypt) for a stored TOTP secret."""

    if not stored:
        return None, False
    if TOTP_PLAIN_RE.match(stored):
        return stored, encryption.is_available()
    try:
        return encryption.decrypt(stored), False
    except Exception as e:
        logger.critical(
            f"Cannot decrypt TOTP secret ({type(e).__name__}) — ENCRYPTION_KEY in secret.env is missing or was changed. "
            "Affected users can't log in until their TOTP is reset, see README 'Lost or changed ENCRYPTION_KEY'."
        )
        return None, False


TOTP_VALID_WINDOW = 1

def match_totp_counter(secret, code):
    """Returns the time step a TOTP code belongs to (±1 step), or None."""

    code = (code or "").strip()
    if not re.fullmatch(r'\d{6}', code):
        return None
    totp = pyotp.TOTP(secret)
    current = int(time.time()) // totp.interval
    for counter in range(current - TOTP_VALID_WINDOW, current + TOTP_VALID_WINDOW + 1):
        if hmac.compare_digest(totp.generate_otp(counter), code):
            return counter
    return None


def consume_totp_code(cur, username, secret, code):
    """Checks a TOTP code and marks it as used, so it can't be used twice."""

    counter = match_totp_counter(secret, code)
    if counter is None:
        return False
    cur.execute("""
        UPDATE user SET totp_last_counter = %s
        WHERE name = %s AND (totp_last_counter IS NULL OR totp_last_counter < %s)
    """, (counter, username, counter))
    return cur.rowcount == 1


REQUIRED_SECRET_KEYS = ("FLASK_KEY", "DB_USER", "DB_PW", "DB_IP", "DB_PORT")

missing_secret_keys = [key for key in REQUIRED_SECRET_KEYS if not secret_config.get(key)]
if missing_secret_keys:
    logger.critical(f"secret.env is missing required values: {', '.join(missing_secret_keys)} — NetPAC can't start")
    raise SystemExit(f"NetPAC: secret.env is missing required values: {', '.join(missing_secret_keys)}")

try:
    db_port = int(secret_config["DB_PORT"])
except ValueError:
    logger.critical(f"DB_PORT in secret.env is not a number: {secret_config['DB_PORT']!r} — NetPAC can't start")
    raise SystemExit("NetPAC: DB_PORT in secret.env must be a number")

flask_key = secret_config["FLASK_KEY"]
db_user = secret_config["DB_USER"]
db_pw = secret_config["DB_PW"]
db_ip = secret_config["DB_IP"]


# --------------------
#   Flask parameter
# --------------------
app = Flask(__name__)
bcrypt = Bcrypt(app)
DUMMY_PASSWORD_HASH = bcrypt.generate_password_hash(uuid.uuid4().hex).decode('utf-8')
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
    """Loads the list of local frontend libraries from static/vendor/manifest.json."""

    try:
        with open(os.path.join(dir_path, "static", "vendor", "manifest.json"), "r", encoding="utf-8") as f:
            return {name: lib for name, lib in json.load(f).items() if not name.startswith("_")}
    except Exception as e:
        logger.error(f"Could not load static/vendor/manifest.json: {e}")
        return {}

VENDOR_LIBS = load_vendor_manifest()


_static_hashes = {}

def static_file_hash(filename):
    """Returns a short content hash of a static file for cache busting."""

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
    """Provides version, static_file() and limits to all templates."""

    def static_file(filename):
        """Returns the URL of a static file with its cache-busting hash."""

        return url_for("static", filename=filename, v=static_file_hash(filename))
    return {"app_version": APP_VERSION, "static_file": static_file,
            "max_script_vars": MAX_SCRIPT_VARS, "max_username_length": MAX_USERNAME_LENGTH}


@app.template_filter("filesize")
def filesize_filter(size):
    """Formats a byte count as B, KB or MB."""

    if size is None:
        return ""
    for unit in ("B", "KB", "MB"):
        if size < 1024 or unit == "MB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


@app.context_processor
def inject_vendor():
    """Provides vendor() to all templates."""

    def vendor(name, key):
        """Returns the URL of a file from a local frontend library."""

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
    """Returns the client IP (behind nginx, resolved by ProxyFix)."""

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
    """Loads the RADIUS settings (without the secret)."""

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


RADIUS_ENFORCE_MA = "enforce_ma" in inspect.signature(Client.__init__).parameters
RADIUS_TIMEOUT_HINT = ("No valid reply from the RADIUS server — it is unreachable, the shared secret is wrong, "
                       "or the server doesn't send a Message-Authenticator (required against BlastRADIUS)")

RADIUS_CAN_VERIFY_MA = hasattr(pyrad.packet.Packet, "verify_message_authenticator")
RADIUS_MA_MISSING_HINT = ("The RADIUS reply has no valid Message-Authenticator — enable it on the RADIUS server "
                          "(required against BlastRADIUS, CVE-2024-3596)")

if not RADIUS_ENFORCE_MA and not RADIUS_CAN_VERIFY_MA:
    logger.warning("The installed pyrad version can't verify the Message-Authenticator of RADIUS replies "
                   "(BlastRADIUS, CVE-2024-3596). Update pyrad to close this.")


def make_radius_client(server_host, server_port, secret, timeout):
    """Creates a RADIUS client that requires a Message-Authenticator if supported."""

    options = {"enforce_ma": True} if RADIUS_ENFORCE_MA else {}
    return Client(
        server=server_host,
        authport=server_port,
        secret=secret.encode(),
        dict=Dictionary(f"{dir_path}/dictionary"),
        timeout=timeout,
        **options
    )


def radius_reply_is_authentic(req, reply, secret):
    """Returns True if a RADIUS reply carries a valid Message-Authenticator (BlastRADIUS protection)."""

    if RADIUS_ENFORCE_MA or not RADIUS_CAN_VERIFY_MA:
        return True
    if not getattr(reply, "message_authenticator", None):
        return False
    try:
        return reply.verify_message_authenticator(secret=secret.encode(),
                                                  original_authenticator=req.authenticator,
                                                  original_code=req.code)
    except Exception as e:
        logger.error(f"RADIUS Message-Authenticator check failed: {e}")
        return False


def get_radius_secret():
    """Returns the decrypted RADIUS shared secret, or None."""

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
#   Notifications
# --------------------
NOTIFY_STATUSES = ('completed', 'failed', 'timeout', 'cancelled')
NOTIFY_STATUS_ICONS = {'completed': '✅', 'failed': '❌', 'timeout': '⏱️', 'cancelled': '⛔'}
NOTIFY_CHANNELS = ('email', 'matrix')
NOTIFY_JOB_TYPES = ('all', 'python', 'ansible')
NOTIFY_SMTP_SECURITY = ('starttls', 'ssl', 'none')
NOTIFY_SEND_TIMEOUT = 10
NOTIFY_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
NOTIFY_MATRIX_ROOM_RE = re.compile(r'^![^:\s]+(:\S+)?$')


def load_notification_settings(with_secrets=False):
    """Loads SMTP/Matrix settings, optionally with decrypted password and token."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT smtp_host, smtp_port, smtp_security, smtp_user, smtp_encrypted_password, smtp_from,
                   matrix_homeserver, matrix_encrypted_token, base_url
            FROM notification_settings WHERE id = 1
        """)
        row = cur.fetchone()
    except Exception as e:
        logger.error(f"Could not load notification settings: {e}")
        row = None
    finally:
        cur.close()
        conn.close()

    if not row:
        row = (None,) * 9

    smtp_host, smtp_port, smtp_security, smtp_user, smtp_pw_enc, smtp_from, matrix_hs, matrix_token_enc, base_url = row
    cfg = {
        'smtp_host': smtp_host or '',
        'smtp_port': smtp_port or 587,
        'smtp_security': smtp_security or 'starttls',
        'smtp_user': smtp_user or '',
        'smtp_password_set': bool(smtp_pw_enc),
        'smtp_from': smtp_from or '',
        'matrix_homeserver': matrix_hs or '',
        'matrix_token_set': bool(matrix_token_enc),
        'base_url': base_url or '',
    }

    if with_secrets:
        for key, enc in (('smtp_password', smtp_pw_enc), ('matrix_token', matrix_token_enc)):
            cfg[key] = None
            if enc:
                try:
                    cfg[key] = encryption.decrypt(enc)
                except Exception as e:
                    logger.error(f"Failed to decrypt notification {key}: {e}")
    return cfg


def send_notification_mail(cfg, to_addr, subject, body):
    """Sends a notification e-mail via SMTP."""

    if not cfg['smtp_host'] or not cfg['smtp_from']:
        raise ValueError("SMTP host and sender address are not configured")

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = cfg['smtp_from']
    msg['To'] = to_addr
    msg.set_content(body)

    context = ssl.create_default_context()
    if cfg['smtp_security'] == 'ssl':
        server = smtplib.SMTP_SSL(cfg['smtp_host'], cfg['smtp_port'], timeout=NOTIFY_SEND_TIMEOUT, context=context)
    else:
        server = smtplib.SMTP(cfg['smtp_host'], cfg['smtp_port'], timeout=NOTIFY_SEND_TIMEOUT)

    with server:
        if cfg['smtp_security'] == 'starttls':
            server.starttls(context=context)
        if cfg['smtp_user']:
            if not cfg.get('smtp_password'):
                raise ValueError("SMTP user is set but no password is saved")
            server.login(cfg['smtp_user'], cfg['smtp_password'])
        server.send_message(msg)


def send_notification_matrix(cfg, room_id, body, html_body, txn_id):
    """Sends a notification message to a Matrix room."""

    if not cfg['matrix_homeserver'] or not cfg.get('matrix_token'):
        raise ValueError("Matrix homeserver and access token are not configured")

    url = (f"{cfg['matrix_homeserver'].rstrip('/')}/_matrix/client/v3/rooms/"
           f"{urllib.parse.quote(room_id, safe='')}/send/m.room.message/{urllib.parse.quote(txn_id, safe='')}")
    payload = {
        "msgtype": "m.text",
        "body": body,
        "format": "org.matrix.custom.html",
        "formatted_body": html_body,
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        method="PUT",
        headers={"Authorization": f"Bearer {cfg['matrix_token']}", "Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=NOTIFY_SEND_TIMEOUT) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        try:
            details = json.loads(e.read().decode(errors="replace"))
            reason = f"{details.get('errcode', 'unknown')}: {details.get('error', '')}".strip(": ")
        except Exception:
            reason = e.reason
        raise RuntimeError(f"Matrix server returned HTTP {e.code} ({reason})") from None


def send_notification(cfg, channel, target, subject, body, html_body, txn_id):
    """Sends a notification via the given channel (email or matrix)."""

    if channel == 'email':
        send_notification_mail(cfg, target, subject, body)
    elif channel == 'matrix':
        send_notification_matrix(cfg, target, body, html_body, txn_id)
    else:
        raise ValueError(f"Unknown notification channel: {channel}")


def format_duration(seconds):
    """Formats seconds as a short duration like '1m 23s'."""

    if seconds is None:
        return "-"
    minutes, sec = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {sec}s"
    if minutes:
        return f"{minutes}m {sec}s"
    return f"{sec}s"


def build_job_notification(cfg, job_id, job):
    """Builds subject, plain text and HTML of a job notification."""

    status = job['status']
    dry_run = " (dry run)" if job['ansible_dry_run'] else ""
    subject = f"[NetPAC] {NOTIFY_STATUS_ICONS.get(status, '')} {status} – {job['script_name']}{dry_run} (#{job_id})"

    fields = [
        ("Script", f"{job['script_name']} ({job['job_type']}){dry_run}"),
        ("Target", job['target'] or "-"),
        ("Started by", job['user_id']),
        ("Started", str(job['started_at'] or "-")),
        ("Finished", str(job['finished_at'] or "-")),
        ("Duration", format_duration(job['duration'])),
    ]
    link = f"{cfg['base_url'].rstrip('/')}/history/{job_id}" if cfg['base_url'] else None

    lines = [f"NetPAC job #{job_id} {status}", ""]
    lines += [f"{label + ':':<12} {value}" for label, value in fields]
    if link:
        lines += ["", f"Details: {link}"]
    body = "\n".join(lines)

    html = [f"<b>{NOTIFY_STATUS_ICONS.get(status, '')} NetPAC job #{job_id} {Markup.escape(status)}</b><br>"]
    html += [f"<b>{label}:</b> {Markup.escape(value)}<br>" for label, value in fields]
    if link:
        html.append(f'<a href="{Markup.escape(link)}">Open job details</a>')
    return subject, body, "".join(html)


def _notify_job_finished_worker(job_id):
    """Sends the notifications for a finished job (once per job)."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE history_jobs SET notified_at = NOW()
            WHERE job_id = %s AND notified_at IS NULL AND status IN %s
        """, (job_id, NOTIFY_STATUSES))
        conn.commit()
        if cur.rowcount != 1:
            return

        cur.execute("""
            SELECT script_name, user_id, target, status, started_at, finished_at, duration, job_type, ansible_dry_run
            FROM history_jobs WHERE job_id = %s
        """, (job_id,))
        row = cur.fetchone()
        if not row:
            return
        job = dict(zip(['script_name', 'user_id', 'target', 'status', 'started_at', 'finished_at',
                        'duration', 'job_type', 'ansible_dry_run'], row))

        status_column = f"on_{job['status']}"
        cur.execute(f"""
            SELECT rule_id, name, channel, target FROM notification_rules
            WHERE is_active = 1 AND {status_column} = 1
            AND (job_type IS NULL OR job_type IN ('all', %s))
        """, (job['job_type'],))
        rules = cur.fetchall()
    except Exception as e:
        exec_logger.error(f"Notification lookup for job {job_id} failed: {e}")
        return
    finally:
        cur.close()
        conn.close()

    if not rules:
        return

    cfg = load_notification_settings(with_secrets=True)
    subject, body, html_body = build_job_notification(cfg, job_id, job)

    for rule_id, rule_name, channel, target in rules:
        try:
            send_notification(cfg, channel, target, subject, body, html_body, f"netpac-{job_id}-{rule_id}")
            exec_logger.info(f"Notification for job {job_id} ({job['status']}) sent via rule '{sanitize_log(rule_name)}' ({channel})")
        except Exception as e:
            exec_logger.error(f"Notification for job {job_id} via rule '{sanitize_log(rule_name)}' ({channel}) failed: {sanitize_log(repr(e))}")


def notify_job_finished(job_id):
    """Starts sending the notifications for a finished job in the background."""

    thread = threading.Thread(target=_notify_job_finished_worker, args=(job_id,), daemon=True)
    thread.start()


# --------------------
#   SQL Config
# --------------------
def get_db():
    """Opens a new database connection."""

    return pymysql.connect(
        user=db_user,
        password=db_pw,
        host=db_ip,
        database=db_database,
        port=db_port,
        autocommit=True
)


# --------------------
#   Database migrations
# --------------------
try:
    run_migrations(get_db, logger, DB_CNF_FILE, BACKUP_DIR, db_database)
except MigrationError as e:
    logger.critical(f"Database migration failed — NetPAC can't start: {e}")
    raise SystemExit(f"NetPAC: database migration failed: {e}")


# --------------------
#   Audit log
# --------------------
AUDIT_RETENTION_DAYS = 365


def audit(action, target=None, details=None, user=None):
    """Writes an entry to the audit log; never raises, so it can't break the action itself."""

    try:
        ip = None
        if has_request_context():
            ip = get_real_ip()
            if user is None and current_user and current_user.is_authenticated:
                user = current_user.id
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO audit_log (username, ip, action, target, details) VALUES (%s, %s, %s, %s, %s)",
                (str(user or "-")[:100], ip, action, str(target)[:255] if target else None,
                 str(details) if details else None)
            )
        finally:
            cur.close()
            conn.close()
    except Exception as e:
        logger.error(f"Audit log entry '{action}' failed: {e}")


def cleanup_audit_log():
    """Deletes audit log entries older than AUDIT_RETENTION_DAYS."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM audit_log WHERE created_at < DATE_SUB(NOW(), INTERVAL %s DAY)", (AUDIT_RETENTION_DAYS,))
        conn.commit()
        if cur.rowcount:
            scheduler_logger.info(f"Audit log cleanup: {cur.rowcount} entries older than {AUDIT_RETENTION_DAYS} days deleted")
    except Exception as e:
        scheduler_logger.error(f"Audit log cleanup failed: {e}")
    finally:
        cur.close()
        conn.close()


# --------------------
#   Schedule Config
# --------------------
jobstore_url = (f"mysql+pymysql://{urllib.parse.quote_plus(db_user or '')}:{urllib.parse.quote_plus(db_pw or '')}"
                f"@{db_ip}:{db_port}/{db_database}")
jobstores = {'default': SQLAlchemyJobStore(url=jobstore_url)}

scheduler = BackgroundScheduler(jobstores=jobstores)
scheduler.start(paused=True)
scheduler_logger.info("Scheduler initialized in paused mode (web worker) — job execution handled by netpac-scheduler.service")

def parse_schedule(expression):
    """Splits a cron expression into the fields APScheduler expects."""

    parts = expression.split()
    return {
        'minute': parts[0],
        'hour': parts[1],
        'day': parts[2],
        'month': parts[3],
        'day_of_week': parts[4]
    }

def trigger_schedule_job(job_id, script_name, user_id, target, variables, secrets_json, use_venv=False, job_type='python'):
    """Queues a scheduled script or playbook (called by the scheduler); the executor runs it."""

    conn = get_db()
    cur = conn.cursor()
    vars_dict = json.loads(variables) if variables else {}
    
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
            WHERE script_name = %s AND COALESCE(target, '') = %s AND job_type = %s AND status = 'planned'
        """, (script_name, target or "", job_type))
        if cur.fetchone()[0] > 0:
            exec_logger.info(f"Schedule #{job_id} ({sanitize_log(script_name)}) is still queued from its last run, skipping")
            return

        if job_type == 'ansible':
            extra_vars = vars_dict.get('extra_vars', {})
            payload = {"extra_vars": json.dumps(extra_vars) if extra_vars else ""}
        else:
            payload = {"variables": variables, "use_venv": bool(use_venv)}
        queued_id = enqueue_job(script_name, user_id, target, variables, secrets_json, job_type, payload)
        exec_logger.info(f"Schedule #{job_id} ({sanitize_log(script_name)}) queued as job #{queued_id}")
    finally:
        cur.execute("SELECT RELEASE_LOCK(%s)", (f"job_{script_name}",))
        cur.close()
        conn.close()


SCHEDULE_JOB_COLUMNS = "job_id, script_name, user_id, target, variables, credential, use_venv, job_type, schedule_expression"

def register_schedule_job(job_id, script_name, user_id, target, variables, secrets_json, use_venv, job_type, schedule_expression):
    """Adds or replaces a schedule in APScheduler."""

    scheduler.add_job(
        trigger_schedule_job,
        trigger='cron',
        id=str(job_id),
        max_instances=1,
        replace_existing=True,
        kwargs={
            'job_id': job_id,
            'script_name': script_name,
            'user_id': user_id,
            'target': target,
            'variables': variables,
            'secrets_json': secrets_json,
            'use_venv': bool(use_venv),
            'job_type': job_type or 'python'
        },
        **parse_schedule(schedule_expression)
    )


def load_jobs_from_db():
    """Registers all active schedules from the database (scheduler start)."""

    scheduler_logger.info("Loading jobs from DB...")
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"SELECT {SCHEDULE_JOB_COLUMNS} FROM schedule_jobs WHERE is_active = TRUE")
        jobs = cur.fetchall()
        scheduler_logger.info(f"Found {len(jobs)} active jobs")
        cur.close()
        conn.close()

        for job in jobs:
            try:
                register_schedule_job(*job)
                scheduler_logger.info(f"Job-ID {job[0]} loaded: {job[1]} with schedule plan {job[8]}")
            except Exception as e:
                scheduler_logger.error(f"Error loading job {job[0]}: {e}")

    except Exception as e:
        scheduler_logger.error(f"Error in load_jobs_from_db: {e}")


# --------------------
#   Environment for child processes
# --------------------
TOOL_PATH_PREFIX = '/usr/bin:/usr/local/bin:'

JOB_ENV_WHITELIST = (
    'PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'LANG', 'LANGUAGE', 'LC_ALL', 'LC_CTYPE', 'TZ', 'TMPDIR',
    'http_proxy', 'https_proxy', 'no_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY',
    'REQUESTS_CA_BUNDLE', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
    'ANSIBLE_CONFIG', 'ANSIBLE_COLLECTIONS_PATH', 'ANSIBLE_COLLECTIONS_PATHS',
)

def tool_env(**extra):
    """Environment for NetPAC's own tools (pip, git, ansible-galaxy, mysqldump)."""

    env = os.environ.copy()
    env['PATH'] = TOOL_PATH_PREFIX + env.get('PATH', '')
    env.update(extra)
    return env


def job_env(**extra):
    """Minimal environment for user scripts and playbooks (whitelist only)."""

    env = {key: value for key, value in os.environ.items() if key in JOB_ENV_WHITELIST}
    env['PATH'] = TOOL_PATH_PREFIX + env.get('PATH', '')
    env.update(extra)
    return env


# --------------------
#   Validate path
# --------------------
SCRIPTS_DIR = "/var/lib/netpac/scripts"
PLAYBOOKS_DIR = "/var/lib/netpac/playbooks"
GIT_DIR = "/var/lib/netpac/git"
PLAYBOOK_EXTENSIONS = ('.yml', '.yaml')

def is_safe_path(target: str, base_dir: str) -> bool:
    """Returns True if a path stays inside base_dir (symlinks resolved)."""

    base_dir = os.path.realpath(base_dir)
    target = os.path.realpath(target)
    return target == base_dir or target.startswith(base_dir + os.sep)


def resolve_repo_path(subpath, local_dir):
    """Maps a UI path (local or git/...) to (base_dir, real path); real path is None if unsafe."""

    if subpath == "git" or subpath.startswith("git/"):
        base_dir = os.path.realpath(GIT_DIR)
        rel_path = subpath[len("git"):].lstrip("/")
    else:
        base_dir = os.path.realpath(local_dir)
        rel_path = subpath

    target = os.path.realpath(os.path.join(base_dir, rel_path))
    if not is_safe_path(target, base_dir) or is_in_git_metadata(target, base_dir):
        return base_dir, None
    return base_dir, target


def is_in_git_metadata(path, base_dir):
    """Returns True if a path lies inside a .git folder."""

    return ".git" in os.path.relpath(path, base_dir).split(os.sep)


def is_listable(path, base_dir):
    """Returns True if a file may be shown in lists (no symlink out of the folder or into .git)."""

    real = os.path.realpath(path)
    return is_safe_path(real, base_dir) and not is_in_git_metadata(real, os.path.realpath(base_dir))


def list_repo_files(local_dir, extensions):
    """Lists all matching files of a folder and the Git checkout (prefixed 'git/')."""

    result = []
    roots = [(local_dir, "")]
    if os.path.exists(GIT_DIR):
        roots.append((GIT_DIR, "git/"))

    for base, prefix in roots:
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d != '.git']
            for file in files:
                full_path = os.path.join(root, file)
                if file.endswith(extensions) and is_listable(full_path, base):
                    result.append(prefix + os.path.relpath(full_path, base))
    return sorted(result)


def file_entry(full_path, name, path):
    """Returns name, path and details (item count or size, last change) of a file or folder."""

    is_dir = os.path.isdir(full_path)
    entry = {"name": name, "path": path, "is_dir": is_dir, "count": None, "size": None, "modified": None}
    try:
        entry["modified"] = datetime.fromtimestamp(os.stat(full_path).st_mtime)
        if is_dir:
            entry["count"] = len([n for n in os.listdir(full_path) if n != '.git'])
        else:
            entry["size"] = os.path.getsize(full_path)
    except OSError:
        pass
    return entry


def sort_entries(entries):
    """Sorts folders first, then files, each alphabetically."""

    return sorted(entries, key=lambda e: (not e["is_dir"], e["name"].lower()))


def repo_file_entries(local_dir, extensions):
    """Like list_repo_files(), but with details for each file (for the search lists)."""

    entries = []
    for rel in list_repo_files(local_dir, extensions):
        full = os.path.join(GIT_DIR, rel[4:]) if rel.startswith("git/") else os.path.join(local_dir, rel)
        entries.append(file_entry(full, rel, rel))
    return entries


def list_dir_entries(target, subpath, base_dir):
    """Lists the entries of one folder for the file browser, folders first."""

    entries = []
    for name in (os.listdir(target) if os.path.isdir(target) else []):
        full = os.path.join(target, name)
        if name == '.git' or not is_listable(full, base_dir):
            continue
        entries.append(file_entry(full, name, os.path.join(subpath, name) if subpath else name))
    return sort_entries(entries)


def load_secret_choices():
    """Returns name and username of all secrets for selection fields."""

    if not encryption.is_available():
        return []
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT name, username, secret_type FROM secrets ORDER BY name")
        return [{'name': row[0], 'username': row[1], 'type': row[2], 'type_label': SECRET_TYPES.get(row[2], row[2])}
                for row in cur.fetchall()]
    finally:
        cur.close()
        conn.close()


def parse_extra_vars(raw):
    """Parses 'Key=Value' lines into a dict."""

    extra_vars = {}
    for line in (raw or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip()
            if key:
                extra_vars[key] = value
    return extra_vars


# --------------------
#   Stale job cleanup
# --------------------
STALE_JOB_NO_PID_SECONDS = 600
JOB_CANCELLED_NOTE = "\n[NetPAC] Job was cancelled.\n"

def is_process_alive(pid: int) -> bool:
    """Returns True if a process with this PID exists."""

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def reap_stale_jobs():
    """Marks running jobs whose process is gone as failed."""

    conn = get_db()
    cur = conn.cursor()
    reaped = []
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
            reaped.append(job_id)
        conn.commit()
    except Exception as e:
        exec_logger.error(f"Error while cleaning up stale jobs: {e}")
        reaped = []
    finally:
        cur.close()
        conn.close()

    for job_id in reaped:
        notify_job_finished(job_id)


# --------------------
#   Job queue and executor
# --------------------

MAX_PARALLEL_JOBS = 5
EXECUTOR_POLL_SECONDS = 1
EXECUTOR_LOCK = "netpac_executor_claim"
LOCAL_HOSTS = {"", "localhost"}


def encode_payload(data):
    """Serializes the run parameters of a queued job (encrypted when a key is configured)."""

    text = json.dumps(data)
    return encryption.encrypt(text) if encryption.is_available() else text


def decode_payload(raw):
    """Reads the run parameters stored by encode_payload()."""

    if not raw:
        return {}
    return json.loads(raw if raw.startswith("{") else encryption.decrypt(raw))


def enqueue_job(script_name, user_id, target, variables, credential, job_type, payload, dry_run=False):
    """Adds a job to the queue (status 'planned'); the executor service starts it. Returns the job id."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO history_jobs
            (script_name, user_id, target, variables, status, started_at, credential, job_type, ansible_dry_run, run_payload)
            VALUES (%s, %s, %s, %s, 'planned', NOW(), %s, %s, %s, %s)
        """, (script_name, user_id, target, variables, credential, job_type, bool(dry_run), encode_payload(payload)))
        conn.commit()
        return cur.lastrowid
    finally:
        cur.close()
        conn.close()


def resolve_job_hosts(cur, target, job_type):
    """Returns the hostnames a job targets, using the same rules as the job execution."""

    if job_type == "ansible" and target == "localhost":
        return {"localhost"}

    hosts = set()
    for item in (target or "").split(","):
        item = item.strip()
        if not item:
            continue
        cur.execute("""
            SELECT DISTINCT h.hostname FROM hosts h
            JOIN host_group_membership m ON h.host_id = m.host_id
            JOIN host_groups g ON m.group_id = g.group_id
            WHERE g.name = %s AND h.is_active = TRUE
        """, (item,))
        group_hosts = {row[0] for row in cur.fetchall()}
        if group_hosts:
            hosts |= group_hosts
            continue
        cur.execute("SELECT hostname FROM hosts WHERE hostname = %s AND is_active = TRUE", (item,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Target '{item}' not found in database")
        hosts.add(row[0])
    return hosts


def jobs_conflict(script_a, stored_a, script_b, stored_b):
    """True if two jobs share a host; jobs without real hosts only conflict with the same script or playbook."""

    hosts_a = set((stored_a or "").split("\n")) - LOCAL_HOSTS
    hosts_b = set((stored_b or "").split("\n")) - LOCAL_HOSTS
    if hosts_a & hosts_b:
        return True
    return script_a == script_b and not hosts_a and not hosts_b


def fail_queued_job(cur, job_id, message):
    """Marks a queued job as failed before it started (e.g. its target no longer exists)."""

    cur.execute("""
        UPDATE history_jobs
        SET status = 'failed', finished_at = NOW(), duration = 0, run_payload = NULL,
            output = CONCAT(COALESCE(output, ''), %s)
        WHERE job_id = %s AND status IN ('planned', 'running')
    """, (f"ERROR: {message}\n", job_id))


def claim_next_jobs():
    """Starts queued jobs in order, up to MAX_PARALLEL_JOBS, skipping those whose hosts are busy."""

    started, failed = [], []
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT GET_LOCK(%s, 5)", (EXECUTOR_LOCK,))
        if cur.fetchone()[0] != 1:
            return
        try:
            cur.execute("SELECT script_name, resolved_hosts FROM history_jobs WHERE status = 'running'")
            running = list(cur.fetchall())
            free_slots = MAX_PARALLEL_JOBS - len(running)
            if free_slots <= 0:
                return

            cur.execute("""
                SELECT job_id, script_name, target, job_type FROM history_jobs
                WHERE status = 'planned' ORDER BY job_id LIMIT 200
            """)
            for job_id, script_name, target, job_type in cur.fetchall():
                if free_slots <= 0:
                    break
                try:
                    hosts = resolve_job_hosts(cur, target, job_type)
                except ValueError as e:
                    fail_queued_job(cur, job_id, str(e))
                    failed.append(job_id)
                    continue

                host_key = "\n".join(sorted(hosts))
                if any(jobs_conflict(name, other, script_name, host_key) for name, other in running):
                    continue

                cur.execute("""
                    UPDATE history_jobs SET status = 'running', started_at = NOW(), resolved_hosts = %s
                    WHERE job_id = %s AND status = 'planned'
                """, (host_key, job_id))
                if cur.rowcount == 1:
                    running.append((script_name, host_key))
                    started.append(job_id)
                    free_slots -= 1
            conn.commit()
        finally:
            cur.execute("SELECT RELEASE_LOCK(%s)", (EXECUTOR_LOCK,))
    finally:
        cur.close()
        conn.close()

    for job_id in failed:
        notify_job_finished(job_id)
    for job_id in started:
        start_claimed_job(job_id)


def start_claimed_job(job_id):
    """Loads a claimed job and runs it in a background thread of the executor."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT script_name, target, credential, job_type, ansible_dry_run, run_payload
            FROM history_jobs WHERE job_id = %s
        """, (job_id,))
        script_name, target, credential, job_type, dry_run, payload_raw = cur.fetchone()
        try:
            payload = decode_payload(payload_raw)
        except Exception as e:
            fail_queued_job(cur, job_id, f"Run parameters could not be read ({type(e).__name__})")
            conn.commit()
            notify_job_finished(job_id)
            return
        cur.execute("UPDATE history_jobs SET run_payload = NULL WHERE job_id = %s", (job_id,))
        conn.commit()
    finally:
        cur.close()
        conn.close()

    secrets = json.loads(credential) if credential else {}
    secret_args = (secrets.get("secret_1", ""), secrets.get("secret_2", ""), secrets.get("secret_3", ""))
    if job_type == "ansible":
        target_fn = execute_playbook_background
        args = (job_id, script_name, target, payload.get("extra_vars", ""), *secret_args, bool(dry_run))
    else:
        target_fn = execute_script_background
        args = (job_id, script_name, target, payload.get("variables", "{}"), payload.get("use_venv", False), *secret_args)

    threading.Thread(target=target_fn, args=args, daemon=True).start()
    exec_logger.info(f"Job #{job_id} ({sanitize_log(script_name)}) started by the executor")


def run_executor():
    """Main loop of the netpac-executor service."""

    exec_logger.info(f"Executor started (max. {MAX_PARALLEL_JOBS} parallel jobs)")
    reap_stale_jobs()
    while True:
        try:
            reap_stale_jobs_throttled()
            claim_next_jobs()
        except Exception as e:
            exec_logger.error(f"Executor loop error: {e}")
        time.sleep(EXECUTOR_POLL_SECONDS)


REAP_THROTTLE_SECONDS = 10
_last_reap = 0.0
_reap_lock = threading.Lock()

def reap_stale_jobs_throttled():
    """Runs reap_stale_jobs() at most every few seconds per worker."""

    global _last_reap
    with _reap_lock:
        if time.time() - _last_reap < REAP_THROTTLE_SECONDS:
            return
        _last_reap = time.time()
    reap_stale_jobs()


HISTORY_RETENTION_DAYS = 180
HISTORY_CLEANUP_BATCH = 1000


def cleanup_job_history():
    """Deletes finished jobs older than HISTORY_RETENTION_DAYS from the job history."""

    deleted = 0
    conn = get_db()
    cur = conn.cursor()
    try:
        while True:
            cur.execute("""
                DELETE FROM history_jobs
                WHERE status NOT IN ('running', 'planned')
                AND COALESCE(finished_at, started_at) < DATE_SUB(NOW(), INTERVAL %s DAY)
                LIMIT %s
            """, (HISTORY_RETENTION_DAYS, HISTORY_CLEANUP_BATCH))
            conn.commit()
            deleted += cur.rowcount
            if cur.rowcount < HISTORY_CLEANUP_BATCH:
                break
    except Exception as e:
        scheduler_logger.error(f"Job history cleanup failed: {e}")
    finally:
        cur.close()
        conn.close()

    if deleted:
        scheduler_logger.info(f"Job history cleanup: {deleted} jobs older than {HISTORY_RETENTION_DAYS} days deleted")
    return deleted


# --------------------
#   Validate script variable count
# --------------------
MAX_SCRIPT_VARS = 10


# --------------------
#   Input validation
# --------------------
MAX_USERNAME_LENGTH = 100
MAX_HOSTNAME_LENGTH = 255

HOSTNAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:-]*\Z')
PIP_INSTALL_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._\-\[\],<>=!~]*\Z')
PIP_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._\-]*\Z')
COLLECTION_INSTALL_RE = re.compile(r'^[A-Za-z0-9_]+\.[A-Za-z0-9_]+(:[A-Za-z0-9._<>=!*,\-]+)?\Z')
COLLECTION_NAME_RE = re.compile(r'^[A-Za-z0-9_]+\.[A-Za-z0-9_]+\Z')


def validate_hostname(hostname):
    """Returns an error message if the hostname is invalid, else None."""

    if not hostname:
        return "Hostname is required"
    if len(hostname) > MAX_HOSTNAME_LENGTH:
        return f"Hostname is too long (max. {MAX_HOSTNAME_LENGTH} characters)"
    if not HOSTNAME_RE.match(hostname):
        return "Hostname may only contain letters, numbers, dots, colons, dashes and underscores (no spaces)"
    return None

def parse_var_count(value) -> int:
    """Returns the number of script variables, limited to MAX_SCRIPT_VARS."""

    try:
        count = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(count, MAX_SCRIPT_VARS))


# --------------------
#   Validate password
# --------------------
def validate_password(password: str) -> str | None:
    """Returns an error message if the password is too weak, else None."""

    if len(password) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return "Password must contain at least one number"
    if not re.search(r'[^A-Za-z0-9]', password):
        return "Password must contain at least one special character"
    return None


# --------------------
#   Loginmanager
# --------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"


# --------------------
#   Define user
# --------------------
class User(UserMixin):
    """Logged-in user for Flask-Login."""

    def __init__(self, username):
        """Creates the user object for a username."""

        self.id = username
        self.username = username


# --------------------
#   Load user
# --------------------
def auth_fingerprint(password_hash, totp_secret):
    """Returns a fingerprint that changes when password or TOTP secret change."""

    data = f"{password_hash or ''}|{totp_secret or ''}".encode()
    return hmac.new(flask_key.encode(), data, hashlib.sha256).hexdigest()[:32]


def load_auth_row(cur, username):
    """Loads password hash and TOTP secret of a user."""

    cur.execute("SELECT password, totp_secret FROM user WHERE name = %s", (username,))
    return cur.fetchone()


def remember_auth_state(username):
    """Stores the current fingerprint in the session."""

    conn = get_db()
    cur = conn.cursor()
    try:
        row = load_auth_row(cur, username)
    finally:
        cur.close()
        conn.close()
    if row:
        session["auth_fp"] = auth_fingerprint(*row)


@login_manager.user_loader
def load_user(user_id):
    """Loads the user for each request; logs out sessions with an outdated fingerprint."""

    conn = get_db()
    cur = conn.cursor()
    try:
        row = load_auth_row(cur, user_id)
    finally:
        cur.close()
        conn.close()

    if row is None:
        return None

    if not hmac.compare_digest(session.get("auth_fp", ""), auth_fingerprint(*row)):
        return None

    return User(user_id)


# --------------------
#   Login route
# --------------------
@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    """Login page: checks the password (local or RADIUS) and continues with TOTP."""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        auth_mode = request.form.get("auth_mode")
        

        if not username or not password:
            flash("Username and password required", "danger")
            return redirect(url_for("login"))

        if len(username) > MAX_USERNAME_LENGTH:
            flash("Invalid login details!", "danger")
            return redirect(url_for("login"))
        
        if auth_mode == "local":
            conn = get_db()
            cur = conn.cursor()
            
            try:
                sql = "SELECT password, totp_confirmed FROM user WHERE name = %s"
                cur.execute(sql, (username,))
                row = cur.fetchone()
                
                if row is None or not row[0]:
                    bcrypt.check_password_hash(DUMMY_PASSWORD_HASH, password)
                    logger.warning(f"Login attempt for non-existent or non-local user: {sanitize_log(username)} (IP: {get_real_ip()})")
                    audit("login.failed", username, "unknown user or no local password", user=username)
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
                audit("login.failed", username, "wrong password", user=username)
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
                srv = make_radius_client(radius_cfg['server_host'], radius_cfg['server_port'],
                                         radius_secret, radius_cfg['timeout'])

                req = srv.CreateAuthPacket(
                    code=pyrad.packet.AccessRequest,
                    User_Name=username,
                    NAS_Identifier="NetPAC"
                )
                
                req["User-Password"] = req.PwCrypt(password)
                req.add_message_authenticator()

                reply = srv.SendPacket(req)

                if not radius_reply_is_authentic(req, reply, radius_secret):
                    logger.warning(f"RADIUS login rejected for '{sanitize_log(username)}': {RADIUS_MA_MISSING_HINT}")
                    audit("login.failed", username, "RADIUS reply without valid Message-Authenticator", user=username)
                    flash("Login error occurred!", "danger")
                    return redirect(url_for("login"))
                
                if reply.code == pyrad.packet.AccessAccept:
                    conn = get_db()
                    cur = conn.cursor()
                    
                    try:
                        cur.execute("SELECT totp_confirmed, method FROM user WHERE name = %s", (username,))
                        row = cur.fetchone()

                        if row is not None and row[1] != 'radius':
                            logger.warning(f"RADIUS login rejected for '{sanitize_log(username)}': name belongs to a {row[1]} account (IP: {get_real_ip()})")
                            audit("login.failed", username, f"RADIUS name belongs to a {row[1]} account", user=username)
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
                audit("login.failed", username, "rejected by RADIUS", user=username)
                flash("Invalid login credentials", "danger")
                
            except RadiusTimeout:
                logger.error(f"RADIUS login failed: {RADIUS_TIMEOUT_HINT}")
                flash("Login error occurred!", "danger")
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
    """Shows the TOTP QR code and activates TOTP after the first valid code."""

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

        counter = match_totp_counter(secret, code)
        if counter is not None:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("""
                UPDATE user SET totp_secret = %s, totp_confirmed = TRUE, totp_last_counter = %s
                WHERE name = %s AND NOT COALESCE(totp_confirmed, FALSE)
            """, (encrypt_totp_secret(secret), counter, username))
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
            remember_auth_state(username)
            session.permanent = True
            logger.info(f"Successful TOTP setup and login: {sanitize_log(username)} (method: {method})")
            audit("login.success", username, f"TOTP set up, method: {method}", user=username)
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
    """Checks the TOTP code and completes the login."""

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
        try:
            cur.execute("SELECT totp_secret, method FROM user WHERE name = %s", (username,))
            row = cur.fetchone()

            totp_secret, needs_reencrypt = decrypt_totp_secret(row[0] if row else None)
            if not totp_secret:
                session.clear()
                if row and row[0]:
                    flash("Your two-factor secret can't be read on the server. Contact your administrator.", "danger")
                return redirect(url_for("login"))

            method = row[1]
            code_ok = consume_totp_code(cur, username, totp_secret, code)
            conn.commit()

            if code_ok and needs_reencrypt:
                try:
                    cur.execute("UPDATE user SET totp_secret = %s WHERE name = %s", (encrypt_totp_secret(totp_secret), username))
                    conn.commit()
                    logger.info(f"TOTP secret of {sanitize_log(username)} migrated to encrypted storage")
                except Exception as e:
                    logger.error(f"Could not re-encrypt TOTP secret of {sanitize_log(username)}: {e}")
        finally:
            cur.close()
            conn.close()

        if code_ok:
            session.pop("pre_auth_user", None)
            user = User(username)
            login_user(user)
            remember_auth_state(username)
            session.permanent = True
            logger.info(f"Successful login: {sanitize_log(username)} (method: {method})")
            audit("login.success", username, f"method: {method}", user=username)
            return redirect(url_for("dashboard"))
        else:
            audit("login.failed", username, "wrong or reused TOTP code", user=username)
            flash("Invalid or already used code — wait for the next code", "danger")

    return render_template("totp_verify.html")


# --------------------
#   TOTP abort
# --------------------
@app.route("/totp/abort", methods=["POST"])
def totp_abort():
    """Aborts the login and clears the session."""

    session.clear()
    return redirect(url_for("login"))


# --------------------
#   Favicon
# --------------------
@app.route('/favicon.ico')
def favicon():
    """Serves the favicon."""

    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', mimetype='image/vnd.microsoft.icon')


# --------------------
#   Dashboard route
# --------------------
@app.route("/dashboard")
@login_required
def dashboard():
    """Dashboard with job statistics and charts."""

    def load_md(filename):
        """Loads a Markdown file from static/ as HTML."""

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
    """Lists all host groups."""

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


def normalize_group_vars(raw):
    """Normalises group variables to one 'key=value' per line."""

    return "\n".join(line.strip() for line in raw.splitlines() if "=" in line and line.strip())


@app.route("/groups", methods=["POST"])
@login_required
def add_group():
    """Creates a host group."""

    name = request.form.get("name", "").strip()
    ansible_vars = normalize_group_vars(request.form.get("ansible_vars", ""))

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
        audit("group.create", name)
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
    """Updates the Ansible variables of a group."""

    ansible_vars = normalize_group_vars(request.form.get("ansible_vars", ""))

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
        logger.info(f"Group '{sanitize_log(row[0])}' updated by {current_user.id}")
        audit("group.update", row[0])
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
    """Deletes a host group."""

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
        audit("group.delete", row[0])
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
    """Returns {hostname: 'group1,group2'}, optionally for one group only."""

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
    """Lists the hosts of one group."""

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT name FROM host_groups WHERE group_id = %s", (group_id,))
        group_row = cur.fetchone()
        if not group_row:
            abort(404)
        group_name = group_row[0]

        cur.execute("""
            SELECT h.host_id, h.hostname, h.description, h.is_active
            FROM hosts h
            JOIN host_group_membership m ON h.host_id = m.host_id
            WHERE m.group_id = %s
            ORDER BY h.hostname
        """, (group_id,))
        all_hosts = cur.fetchall()

        host_groups = load_host_group_names(cur, group_id)

        cur.execute("SELECT group_id, name, ansible_vars FROM host_groups ORDER BY name")
        available_groups = cur.fetchall()

    except HTTPException:
        raise
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
    """Lists all hosts."""

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT host_id, hostname, description, is_active FROM hosts ORDER BY hostname")
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
    """Creates a host with its groups."""

    hostname = request.form.get("Hostname", "").strip()
    description = request.form.get("Description", "").strip()
    group_ids = request.form.getlist("group_ids")

    error = validate_hostname(hostname)
    if error:
        flash(error, "danger")
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
        logger.info(f"Host '{sanitize_log(hostname)}' added with groups {group_ids} by {current_user.id}")
        audit("host.create", hostname, f"groups: {group_ids}")
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
    """Updates name, description and groups of a host."""

    original_hostname = request.form.get("OriginalHostname", "").strip()
    hostname = request.form.get("Hostname", "").strip()
    description = request.form.get("Description", "").strip()
    group_ids = request.form.getlist("group_ids")

    error = validate_hostname(hostname)
    if error:
        flash(error, "danger")
        return redirect(url_for("hosts"))

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
        logger.info(f"Host '{sanitize_log(original_hostname)}' updated (now '{sanitize_log(hostname)}', groups {group_ids}) by {current_user.id}")
        audit("host.update", original_hostname, f"now: {hostname}, groups: {group_ids}")
        flash(f"Host '{hostname}' updated", "success")

    except Exception as e:
        logger.error(f"Exception on update_host: {type(e).__name__}: {e}")
        conn.rollback()
        flash("Error updating host", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("hosts"))


@app.route("/hosts/edit/bulk", methods=["POST"])
@login_required
def bulk_update_hosts():
    """Adds groups and/or sets the description for several hosts."""

    host_ids = request.form.getlist("host_ids")
    description = request.form.get("Description", "").strip()
    group_ids = request.form.getlist("group_ids")

    if not host_ids:
        flash("No hosts selected for bulk edit", "danger")
        return redirect(url_for("hosts"))

    conn = get_db()
    cur = conn.cursor()

    try:
        conn.begin()
        for host_id in host_ids:
            
            if description:
                cur.execute("UPDATE hosts SET description = %s WHERE host_id = %s", (description, host_id))
 
            for gid in group_ids:
                if gid:
                    cur.execute("INSERT IGNORE INTO host_group_membership (host_id, group_id) VALUES (%s, %s)", (host_id, gid))

        conn.commit()
        logger.info(f"Bulk updated hosts {host_ids} with description '{sanitize_log(description)}' and groups {group_ids} by {current_user.id}")
        audit("host.bulk_update", f"{len(host_ids)} hosts", f"description: {description!r}, groups: {group_ids}")
        flash(f"Bulk updated {len(host_ids)} hosts", "success")

    except Exception as e:
        logger.error(f"Exception on bulk_update_hosts: {type(e).__name__}: {e}")
        conn.rollback()
        flash("Error updating hosts in bulk", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("hosts"))


@app.route("/hosts/toggle/<int:host_id>", methods=["POST"])
@login_required
def toggle_host(host_id):
    """Activates or deactivates a host."""

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT is_active FROM hosts WHERE host_id = %s", (host_id,))
        row = cur.fetchone()

        if not row:
            abort(404)

        cur.execute("UPDATE hosts SET is_active = NOT is_active WHERE host_id = %s", (host_id,))
        conn.commit()

        logger.info(f"Host {host_id} {'deactivated' if row[0] else 'activated'} by {current_user.id}")
        audit("host.toggle", str(host_id), "deactivated" if row[0] else "activated")
        flash("Host updated", "success")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling host {host_id}: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

    return redirect(request.referrer or url_for("hosts"))


@app.route("/hosts/delete", methods=["POST"])
@login_required
def delete_host():
    """Deletes a host."""

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
        logger.info(f"Host '{sanitize_log(hostname)}' deleted by {current_user.id}")
        audit("host.delete", hostname)

    except Exception as e:
        logger.error(f"Error deleting host '{sanitize_log(hostname)}': {e}")
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
    """Loads the Git repository settings from git_config.json."""

    if os.path.exists(GIT_CONFIG_FILE):
        try:
            with open(GIT_CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"repo_url": "", "branch": "main", "token_encrypted": ""}


def build_git_env(token: str) -> dict:
    """Environment for git with the access token as auth header."""

    env = tool_env(GIT_TERMINAL_PROMPT='0')
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
    """Script overview with folders and all Python scripts."""

    if not os.path.isdir(SCRIPTS_DIR):
        logger.error(f"Script directory {SCRIPTS_DIR} does not exist")
        flash(f"Script directory {SCRIPTS_DIR} does not exist — run setup.sh again or create it", "warning")

    entries = [e for e in list_dir_entries(SCRIPTS_DIR, "", SCRIPTS_DIR) if e["is_dir"] or e["name"].endswith('.py')]
    if os.path.exists(GIT_DIR):
        entries = sort_entries(entries + [file_entry(GIT_DIR, "git", "git")])

    all_scripts = repo_file_entries(SCRIPTS_DIR, ('.py',))

    return render_template("scripts.html", entries=entries, git_config=load_git_config(), current_path="", all_scripts=all_scripts)


@app.route("/scripts/", defaults={"subpath": ""})
@app.route("/scripts/<path:subpath>")
@login_required
def view_script(subpath):
    """Shows a script folder or a script with the run form."""

    base_dir, target = resolve_repo_path(subpath, SCRIPTS_DIR)

    if target is None:
        logger.warning(f"Path traversal attempt detected: {sanitize_log(subpath)}")
        abort(403)

    if not os.path.exists(target):
        abort(404)

    if os.path.isdir(target):
        return render_template("scripts.html", entries=list_dir_entries(target, subpath, base_dir), current_path=subpath, git_config=load_git_config())

    try:
        with open(target, "r", encoding="utf-8") as f:
            content = f.read()

        return render_template("view_script.html", filename=subpath, content=content, secrets=load_secret_choices())

    except Exception as e:
        logger.error(f"Error reading script {subpath}: {e}")
        abort(500)


@app.route("/run_scripts/<path:subpath>", methods=["POST"])
@login_required
def run_script(subpath):
    """Starts a Python script as a background job."""

    _, target_path = resolve_repo_path(subpath, SCRIPTS_DIR)

    if target_path is None:
        logger.warning(f"Path traversal attempt detected: {sanitize_log(subpath)}")
        abort(403)
    
    
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
    
    use_venv = request.form.get("use_venv") == "on"

    try:
        job_id = enqueue_job(safe_filename, current_user.id, target, variables, json.dumps(secrets_json), 'python',
                             {"variables": variables, "use_venv": use_venv})
    except Exception as e:
        logger.error(f"Failed to queue job: {e}")
        flash("Failed to queue the script", "danger")
        return redirect(url_for("scripts"))

    exec_logger.info(f"Script '{sanitize_log(safe_filename)}' queued as job #{job_id} by {current_user.id}")
    audit("job.start", safe_filename, f"job #{job_id}")
    flash(f"Script '{safe_filename}' queued (Job #{job_id})", "success")
    return redirect(url_for("history", mode="python"))


# --------------------
#   Background Script execution
# --------------------
def execute_script_background(job_id, filename, target, variables, use_venv, secret_1, secret_2, secret_3):
    """Runs a Python script and stores output and result in the job history."""

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
    temp_files = []
    env = job_env(PYTHONUNBUFFERED='1')

    process = None 

    conn = get_db()
    cur = conn.cursor()

    def append_live_output(text):
        """Appends new output to the job while it is running."""

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
                    WHERE g.name = %s and h.is_active = True
                """, (item,))
                group_matches = cur.fetchall()

                if group_matches:
                    resolved.update(row[0] for row in group_matches)
                else:
                    cur.execute("SELECT DISTINCT hostname FROM hosts WHERE hostname = %s and is_active = True", (item,))
                    host_match = cur.fetchall()
                    if host_match:
                        resolved.update(row[0] for row in host_match)
                    else:
                        raise ValueError(f"Target '{item}' not found in database")

            targets = [(h,) for h in sorted(resolved)]
        else:
            targets = []

        prepare_job_secrets(cur, [secret_1, secret_2, secret_3], env, temp_files)

        fd, temp_hostfile = tempfile.mkstemp(prefix="netpac_hosts_", suffix=".txt")
        with os.fdopen(fd, "w") as f:
            for t in targets:
                f.write(t[0] + "\n")

        _, script_path = resolve_repo_path(filename, SCRIPTS_DIR)

        if script_path is None:
            raise ValueError("Invalid script path")

        if not os.path.isfile(script_path):
            raise FileNotFoundError(f"Script not found: {filename}")

        env['NETPAC_HOSTFILE'] = temp_hostfile
        script_dir = os.path.dirname(script_path)

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
        remove_temp_files(temp_files)

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

        notify_job_finished(job_id)


# --------------------
#   VENV
# --------------------
VENV_DIR = os.path.join(dir_path, 'venv')
VENV_PIP = os.path.join(VENV_DIR, 'bin', 'pip')

@app.route("/venv")
@login_required
def venv_manager():
    """Lists the packages of the Python venv."""

    packages = []
    venv_exists = os.path.exists(VENV_PIP)
    
    if venv_exists:
        env = tool_env()

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
    """Installs a package into the venv."""

    package = request.form.get("package", "").strip()
    
    if not package:
        flash("Package name required", "danger")
        return redirect(url_for("venv_manager"))

    if not PIP_INSTALL_RE.match(package):
        flash("Invalid package name", "danger")
        return redirect(url_for("venv_manager"))

    env = tool_env()

    result = subprocess.run(
        [VENV_PIP, 'install', package],
        capture_output=True, text=True,
        env=env
    )

    if result.returncode == 0:
        logger.info(f"venv package '{package}' installed by {current_user.id}")
        audit("venv.install", package)
        flash(f"Package '{package}' installed successfully", "success")
    else:
        logger.error(f"venv package '{package}' install failed (by {current_user.id}): {sanitize_log(result.stderr)}")
        flash(f"Failed to install '{package}': {result.stderr}", "danger")

    return redirect(url_for("venv_manager"))


@app.route("/venv/uninstall", methods=["POST"])
@login_required
def venv_uninstall():
    """Removes a package from the venv."""

    package = request.form.get("package", "").strip()

    if not package:
        flash("Package name required", "danger")
        return redirect(url_for("venv_manager"))

    if not PIP_NAME_RE.match(package):
        flash("Invalid package name", "danger")
        return redirect(url_for("venv_manager"))

    env = tool_env()

    result = subprocess.run(
        [VENV_PIP, 'uninstall', '-y', package],
        capture_output=True, text=True,
        env=env
    )

    if result.returncode == 0:
        logger.info(f"venv package '{sanitize_log(package)}' removed by {current_user.id}")
        audit("venv.uninstall", package)
        flash(f"Package '{package}' removed", "success")
    else:
        logger.error(f"venv package '{sanitize_log(package)}' removal failed (by {current_user.id}): {sanitize_log(result.stderr)}")
        flash(f"Failed to remove '{package}': {result.stderr}", "danger")

    return redirect(url_for("venv_manager"))


@app.route("/venv/update", methods=["POST"])
@login_required
def venv_update():
    """Updates a package in the venv."""

    package = request.form.get("package", "").strip()

    if not package:
        flash("Package name required", "danger")
        return redirect(url_for("venv_manager"))

    if not PIP_NAME_RE.match(package):
        flash("Invalid package name", "danger")
        return redirect(url_for("venv_manager"))

    env = tool_env()

    result = subprocess.run(
        [VENV_PIP, 'install', '--upgrade', package],
        capture_output=True, text=True,
        env=env
    )

    if result.returncode == 0:
        logger.info(f"venv package '{sanitize_log(package)}' updated by {current_user.id}")
        audit("venv.update", package)
        flash(f"Package '{package}' updated", "success")
    else:
        logger.error(f"venv package '{sanitize_log(package)}' update failed (by {current_user.id}): {sanitize_log(result.stderr)}")
        flash(f"Failed to update '{package}': {result.stderr}", "danger")

    return redirect(url_for("venv_manager"))


@app.route("/venv/update_all", methods=["POST"])
@login_required
def venv_update_all():
    """Updates all outdated packages in the venv."""

    env = tool_env()

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
        logger.info(f"venv: {len(outdated)} packages updated by {current_user.id}")
        audit("venv.update_all", None, f"{len(outdated)} packages")
        flash(f"Updated {len(outdated)} packages", "success")
    else:
        logger.error(f"venv update check failed (by {current_user.id}): {sanitize_log(result.stderr)}")
        flash("Failed to check for updates", "danger")

    return redirect(url_for("venv_manager"))


# ---------------------
#   Scripts Git Sync
# ---------------------
@app.route("/scripts/sync", methods=["POST"])
@login_required
def sync_scripts():
    """Clones or pulls the configured Git repository."""

    git_config  = load_git_config()
    repo_url    = git_config.get("repo_url", "")
    branch      = git_config.get("branch", "main")
    token_enc   = git_config.get("token_encrypted", "")
    git_dir = GIT_DIR

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
            audit("git.sync", repo_url, f"branch: {branch}")
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
    """Shows a playbook folder or a playbook with the run form."""

    base_dir, target = resolve_repo_path(subpath, PLAYBOOKS_DIR)

    if target is None:
        logger.warning(f"Path traversal attempt detected: {sanitize_log(subpath)}")
        abort(403)

    if subpath == "" and not os.path.isdir(target):
        logger.error(f"Playbook directory {target} does not exist")
        flash(f"Playbook directory {target} does not exist — run setup.sh again or create it", "warning")
    elif not os.path.exists(target):
        abort(404)

    if subpath == "" or os.path.isdir(target):
        entries = list_dir_entries(target, subpath, base_dir)
        if subpath == "" and os.path.exists(GIT_DIR):
            entries = sort_entries(entries + [file_entry(GIT_DIR, "git", "git")])

        all_playbooks = repo_file_entries(PLAYBOOKS_DIR, PLAYBOOK_EXTENSIONS)

        return render_template("playbooks.html", entries=entries, all_playbooks=all_playbooks, secrets=load_secret_choices(), current_path=subpath, git_config=load_git_config())

    elif os.path.isfile(target) and target.endswith(PLAYBOOK_EXTENSIONS):
        try:
            with open(target, "r", encoding="utf-8") as f:
                content = f.read()

            return render_template("view_playbook.html", filename=subpath, content=content, secrets=load_secret_choices())

        except Exception as e:
            logger.error(f"Error reading playbook {subpath}: {e}")
            abort(500)

    abort(404)


@app.route("/playbook_graph/<path:subpath>", methods=["POST"])
@login_required
def playbook_graph(subpath):
    """Generates a graph of a playbook with ansible-playbook-grapher."""

    _, target = resolve_repo_path(subpath, PLAYBOOKS_DIR)

    if target is None:
        logger.warning(f"Path traversal attempt detected: {sanitize_log(subpath)}")
        abort(403)

    os.makedirs(GRAPH_DIR, exist_ok=True)

    graph_name = subpath.replace("/", "_").replace(".yml", "").replace(".yaml", "")
    output_path = os.path.join(GRAPH_DIR, graph_name)

    grapher = os.path.join(dir_path, "venv", "bin", "ansible-playbook-grapher")

    if not os.path.exists(grapher) and not shutil.which("ansible-playbook-grapher"):
        flash("ansible-playbook-grapher is not installed. Install it manually over the Web-Interface -> Python -> Environment", "danger")
        return redirect(url_for("browse_playbooks", subpath=subpath))
    
    env = tool_env()

    result = subprocess.run(
        [grapher, target, "-o", output_path],
        capture_output=True, text=True,
        env=env
    )

    if result.returncode != 0:
        flash(f"Graph generation failed: {result.stderr}", "danger")
        return redirect(url_for("browse_playbooks", subpath=subpath))

    return redirect(url_for("view_playbook_graph", filename=graph_name))


GRAPH_DIR = "/var/lib/netpac/graphs"

def resolve_graph_path(filename):
    """Returns (graph_dir, svg_path) of a graph or aborts with 403/404."""

    graph_dir = os.path.realpath(GRAPH_DIR)
    graph_path = os.path.realpath(os.path.join(graph_dir, filename + ".svg"))

    if not is_safe_path(graph_path, graph_dir):
        logger.warning(f"Path traversal attempt detected: {sanitize_log(filename)}")
        abort(403)

    if not os.path.isfile(graph_path):
        abort(404)

    return graph_dir, graph_path


@app.route("/playbook_graph/view/<filename>")
@login_required
def view_playbook_graph(filename):
    """Page that shows a playbook graph."""

    resolve_graph_path(filename)
    return render_template("playbook_graph.html", filename=filename)


@app.route("/playbook_graph/raw/<filename>.svg")
@login_required
def raw_playbook_graph(filename):
    """Serves the graph SVG with a CSP that blocks scripts."""

    graph_dir, graph_path = resolve_graph_path(filename)

    response = make_response(send_from_directory(graph_dir, os.path.basename(graph_path), mimetype="image/svg+xml"))
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/playbook_syntax_check/<path:subpath>", methods=["POST"])
@login_required
def playbook_syntax_check(subpath):
    """Runs ansible-playbook --syntax-check on a playbook."""

    _, target = resolve_repo_path(subpath, PLAYBOOKS_DIR)

    if target is None:
        logger.warning(f"Path traversal attempt detected: {sanitize_log(subpath)}")
        abort(403)

    if not os.path.exists(target):
        abort(404)

    ansible = shutil.which("ansible-playbook") or "/usr/bin/ansible-playbook"

    env = tool_env()

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
    """Starts a playbook as a background job."""

    _, target_path = resolve_repo_path(subpath, PLAYBOOKS_DIR)
    dry_run = request.form.get("dry_run") == "on"

    if target_path is None:
        logger.warning(f"Path traversal attempt detected: {sanitize_log(subpath)}")
        abort(403)

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

    extra_vars = parse_extra_vars(request.form.get("extra_vars_raw", ""))
    extra_vars_str = json.dumps(extra_vars) if extra_vars else ""

    variables = json.dumps({"extra_vars": extra_vars})
    secrets_json = json.dumps({"secret_1": secret_1, "secret_2": secret_2, "secret_3": secret_3})

    try:
        job_id = enqueue_job(subpath, current_user.id, target, variables, secrets_json, 'ansible',
                             {"extra_vars": extra_vars_str}, dry_run)
    except Exception as e:
        logger.error(f"Failed to queue playbook job: {e}")
        flash("Failed to queue the playbook", "danger")
        return redirect(url_for("browse_playbooks", subpath=""))

    exec_logger.info(f"Playbook '{sanitize_log(subpath)}' queued as job #{job_id} by {current_user.id}" + (" (dry run)" if dry_run else ""))
    audit("job.start", subpath, f"job #{job_id}" + (" (dry run)" if dry_run else ""))
    flash(f"Playbook '{subpath}' queued {'(Dry Run) ' if dry_run else ''}(Job #{job_id})", "success")
    return redirect(url_for("history", mode="ansible"))


# --------------------
#   Playbook Templates
# --------------------
@app.route("/playbook_templates")
@login_required
def playbook_templates():
    """Lists all playbook templates."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT template_id, name, description, playbook_path, target, extra_vars, secret_1, secret_2, secret_3, created_at, created_by FROM playbook_templates ORDER BY name")
        rows = cur.fetchall()
        templates = [dict(zip(['template_id','name','description','playbook_path','target','extra_vars','secret_1','secret_2','secret_3','created_at','created_by'], row)) for row in rows]
        for template in templates:
            template['fields'] = load_template_fields(cur, template['template_id'])
    finally:
        cur.close()
        conn.close()

    return render_template("playbook_templates.html", templates=templates,
                           playbooks=list_repo_files(PLAYBOOKS_DIR, PLAYBOOK_EXTENSIONS), secrets=load_secret_choices())


def parse_playbook_target(form):
    """Returns (target, error); localhost must be chosen explicitly."""

    if form.get("run_local") == "on":
        return "localhost", None
    target = form.get("target", "").strip()
    if not target:
        return None, "Please enter a target or choose 'Run on the NetPAC server (localhost)'"
    return target, None


FIELD_TYPES = ("text", "textarea", "number", "select", "multiselect", "boolean", "password")
FIELD_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,99}\Z")
MAX_TEMPLATE_FIELDS = 30
REDACTED_VALUE = "********"


def parse_template_fields(raw):
    """Returns (fields, error) from the JSON sent by the survey field editor."""

    try:
        items = json.loads(raw or "[]")
    except ValueError:
        return None, "Survey fields could not be read"
    if not isinstance(items, list) or len(items) > MAX_TEMPLATE_FIELDS:
        return None, f"At most {MAX_TEMPLATE_FIELDS} survey fields are allowed"

    fields, seen = [], set()
    for item in items:
        if not isinstance(item, dict):
            return None, "Survey fields could not be read"
        var_name = str(item.get("var_name", "")).strip()
        field_type = str(item.get("field_type", "text"))
        label = str(item.get("label", "")).strip()[:255] or var_name
        options = [o.strip() for o in str(item.get("options", "")).splitlines() if o.strip()]
        default = str(item.get("default_value", "")).strip()

        if not FIELD_VAR_RE.match(var_name):
            return None, f"Invalid variable name '{var_name}' (letters, digits and _ only, not starting with a digit)"
        if var_name in seen:
            return None, f"Variable '{var_name}' is used twice"
        if field_type not in FIELD_TYPES:
            return None, f"Invalid field type for '{var_name}'"
        if field_type in ("select", "multiselect") and not options:
            return None, f"Field '{var_name}' needs at least one option (one per line)"
        if field_type == "number" and default:
            try:
                float(default)
            except ValueError:
                return None, f"Default value of '{var_name}' must be a number"
        if field_type == "select" and default and default not in options:
            return None, f"Default value of '{var_name}' must be one of its options"
        if field_type == "password":
            default = ""

        seen.add(var_name)
        fields.append({"var_name": var_name, "label": label, "field_type": field_type,
                       "required": bool(item.get("required")), "default_value": default,
                       "options": options})
    return fields, None


def load_template_fields(cur, template_id):
    """Returns the survey fields of a template in display order."""

    cur.execute("""
        SELECT var_name, label, field_type, required, default_value, options
        FROM template_fields WHERE template_id = %s ORDER BY sort_order, field_id
    """, (template_id,))
    return [{"var_name": r[0], "label": r[1], "field_type": r[2], "required": bool(r[3]),
             "default_value": r[4] or "", "options": [o for o in (r[5] or "").splitlines() if o]}
            for r in cur.fetchall()]


def save_template_fields(cur, template_id, fields):
    """Replaces the survey fields of a template."""

    cur.execute("DELETE FROM template_fields WHERE template_id = %s", (template_id,))
    for order, field in enumerate(fields):
        cur.execute("""
            INSERT INTO template_fields
            (template_id, var_name, label, field_type, required, default_value, options, sort_order)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (template_id, field["var_name"], field["label"], field["field_type"], field["required"],
              field["default_value"] or None, "\n".join(field["options"]) or None, order))


def collect_survey_values(fields, form):
    """Returns (values, error) for the survey fields submitted when launching a template."""

    values = {}
    for field in fields:
        name, field_type = field["var_name"], field["field_type"]
        key = f"field_{name}"

        if field_type == "boolean":
            values[name] = form.get(key) == "on"
            continue
        if field_type == "multiselect":
            chosen = form.getlist(key)
            if any(choice not in field["options"] for choice in chosen):
                return None, f"Invalid choice for '{field['label']}'"
            if field["required"] and not chosen:
                return None, f"'{field['label']}' is required"
            values[name] = chosen
            continue

        raw = form.get(key, "")
        value = raw if field_type in ("textarea", "password") else raw.strip()
        if not value:
            if field["required"]:
                return None, f"'{field['label']}' is required"
            continue
        if field_type == "number":
            try:
                number = float(value)
            except ValueError:
                return None, f"'{field['label']}' must be a number"
            values[name] = int(number) if number.is_integer() else number
        elif field_type == "select":
            if value not in field["options"]:
                return None, f"Invalid choice for '{field['label']}'"
            values[name] = value
        else:
            values[name] = value
    return values, None


@app.route("/playbook_templates/create", methods=["POST"])
@login_required
def create_playbook_template():
    """Creates a playbook template."""

    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    playbook_path = request.form.get("playbook_path", "").strip()
    extra_vars = request.form.get("extra_vars", "").strip()
    secret_1 = request.form.get("secret_1", "").strip()
    secret_2 = request.form.get("secret_2", "").strip()
    secret_3 = request.form.get("secret_3", "").strip()

    if not name or not playbook_path:
        flash("Name and Playbook are required", "danger")
        return redirect(url_for("playbook_templates"))

    target, error = parse_playbook_target(request.form)
    if error:
        flash(error, "danger")
        return redirect(url_for("playbook_templates"))

    fields, error = parse_template_fields(request.form.get("fields_json"))
    if error:
        flash(error, "danger")
        return redirect(url_for("playbook_templates"))

    conn = get_db()
    cur = conn.cursor()
    try:
        conn.begin()
        cur.execute("""
            INSERT INTO playbook_templates
            (name, description, playbook_path, target, extra_vars, secret_1, secret_2, secret_3, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (name, description, playbook_path, target, extra_vars, secret_1, secret_2, secret_3, current_user.id))
        save_template_fields(cur, cur.lastrowid, fields)
        conn.commit()
        logger.info(f"Template '{sanitize_log(name)}' ({sanitize_log(playbook_path)}) created by {current_user.id}")
        audit("template.create", name, f"playbook: {playbook_path}")
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
    """Updates a playbook template."""

    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    playbook_path = request.form.get("playbook_path", "").strip()
    extra_vars = request.form.get("extra_vars", "").strip()
    secret_1 = request.form.get("secret_1", "").strip()
    secret_2 = request.form.get("secret_2", "").strip()
    secret_3 = request.form.get("secret_3", "").strip()

    if not name or not playbook_path:
        flash("Name and Playbook are required", "danger")
        return redirect(url_for("playbook_templates"))

    target, error = parse_playbook_target(request.form)
    if error:
        flash(error, "danger")
        return redirect(url_for("playbook_templates"))

    fields, error = parse_template_fields(request.form.get("fields_json"))
    if error:
        flash(error, "danger")
        return redirect(url_for("playbook_templates"))

    conn = get_db()
    cur = conn.cursor()
    try:
        conn.begin()
        cur.execute("""
            UPDATE playbook_templates
            SET name=%s, description=%s, playbook_path=%s, target=%s,
                extra_vars=%s, secret_1=%s, secret_2=%s, secret_3=%s
            WHERE template_id=%s
        """, (name, description, playbook_path, target, extra_vars, secret_1, secret_2, secret_3, template_id))
        save_template_fields(cur, template_id, fields)
        conn.commit()
        logger.info(f"Template {template_id} ('{sanitize_log(name)}') updated by {current_user.id}")
        audit("template.update", name, f"playbook: {playbook_path}")
        flash(f"Template '{name}' updated", "success")
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to update template {template_id}: {e}")
        flash("Failed to update template", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("playbook_templates"))


@app.route("/playbook_templates/delete/<int:template_id>", methods=["POST"])
@login_required
def delete_playbook_template(template_id):
    """Deletes a playbook template."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM playbook_templates WHERE template_id = %s", (template_id,))
        conn.commit()
        logger.info(f"Template {template_id} deleted by {current_user.id}")
        audit("template.delete", f"#{template_id}")
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
    """Starts a playbook from a template as a background job."""

    dry_run = request.form.get("dry_run") == "on"

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT name, playbook_path, target, extra_vars, secret_1, secret_2, secret_3 FROM playbook_templates WHERE template_id = %s", (template_id,))
        row = cur.fetchone()
        fields = load_template_fields(cur, template_id) if row else []
    finally:
        cur.close()
        conn.close()

    if not row:
        flash("Template not found", "danger")
        return redirect(url_for("playbook_templates"))

    name, playbook_path, target, extra_vars_raw, secret_1, secret_2, secret_3 = row

    if not target:
        flash(f"Template '{name}' has no target. Edit it and enter a target or choose localhost explicitly.", "danger")
        return redirect(url_for("playbook_templates"))

    survey, error = collect_survey_values(fields, request.form)
    if error:
        flash(error, "danger")
        return redirect(url_for("playbook_templates"))

    extra_vars = {**parse_extra_vars(extra_vars_raw), **survey}
    extra_vars_str = json.dumps(extra_vars) if extra_vars else ""

    secret_fields = [f["var_name"] for f in fields if f["field_type"] == "password" and f["var_name"] in survey]
    stored_vars = {k: (REDACTED_VALUE if k in secret_fields else v) for k, v in extra_vars.items()}
    variables = json.dumps({"extra_vars": stored_vars, "template": name, **({"redacted_fields": secret_fields} if secret_fields else {})})
    secrets_json = json.dumps({"secret_1": secret_1 or "", "secret_2": secret_2 or "", "secret_3": secret_3 or ""})

    try:
        job_id = enqueue_job(playbook_path, current_user.id, target, variables, secrets_json, 'ansible',
                             {"extra_vars": extra_vars_str}, dry_run)
    except Exception as e:
        logger.error(f"Failed to queue template job: {e}")
        flash("Failed to launch template", "danger")
        return redirect(url_for("playbook_templates"))

    exec_logger.info(f"Template '{sanitize_log(name)}' queued as job #{job_id} by {current_user.id}" + (" (dry run)" if dry_run else ""))
    audit("template.launch", name, f"job #{job_id}" + (" (dry run)" if dry_run else ""))
    flash(f"Template '{name}' queued {'(Dry Run) ' if dry_run else ''}(Job #{job_id})", "success")
    return redirect(url_for("history", mode="ansible"))


# --------------------
#   Background Playbook execution
# --------------------
def execute_playbook_background(job_id, filename, target, extra_vars_str, secret_1, secret_2, secret_3, dry_run=False):
    """Runs a playbook and stores output and result in the job history."""

    exec_logger.info(f"Background executing playbook: {filename}" + (" (DRY RUN)" if dry_run else ""))


    start_time = datetime.now()
    output_script = ""
    status = "completed"
    temp_inventory = None
    temp_extra_vars = None
    temp_files = []
    env = job_env(PYTHONUNBUFFERED='1', ANSIBLE_FORCE_COLOR='1', ANSIBLE_STDOUT_CALLBACK='default')

    ansible = shutil.which("ansible-playbook") or "/usr/bin/ansible-playbook"

    conn = get_db()
    cur = conn.cursor()

    def append_live_output(text):
        """Appends new output to the job while it is running."""

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
                    WHERE g.name = %s and h.is_active = True;
                """, (item,))
                group_matches = cur.fetchall()

                if group_matches:
                    hostnames = {row[0] for row in group_matches}
                    resolved.update(hostnames)
                    group_host_map.setdefault(item, set()).update(hostnames)
                else:
                    cur.execute("SELECT DISTINCT hostname FROM hosts WHERE hostname = %s and is_active = True", (item,))
                    host_match = cur.fetchall()
                    if host_match:
                        resolved.update(row[0] for row in host_match)
                    else:
                        raise ValueError(f"Target '{item}' not found in database")

            targets = [(h,) for h in sorted(resolved)]

            if resolved:
                placeholders = ", ".join(["%s"] * len(resolved))
                cur.execute(f"""
                    SELECT g.name, h.hostname FROM host_groups g
                    JOIN host_group_membership m ON g.group_id = m.group_id
                    JOIN hosts h ON h.host_id = m.host_id
                    WHERE h.hostname IN ({placeholders})
                """, sorted(resolved))
                for group_name, hostname in cur.fetchall():
                    group_host_map.setdefault(group_name, set()).add(hostname)
        else:
            targets = []
            group_host_map = {}

        secret_args = prepare_job_secrets(cur, [secret_1, secret_2, secret_3], env, temp_files)

        fd, temp_inventory = tempfile.mkstemp(prefix="netpac_inventory_", suffix=".ini")
        with os.fdopen(fd, "w") as f:
            f.write("[targets]\n")
            for t in targets:
                if t[0] == "localhost":
                    f.write("localhost ansible_connection=local\n")
                else:
                    f.write(t[0] + "\n")

            for group_name, hostnames in sorted(group_host_map.items()):
                cur.execute("SELECT ansible_vars FROM host_groups WHERE name = %s", (group_name,))
                row = cur.fetchone()
                group_vars = [v.strip() for v in (row[0] if row and row[0] else "").splitlines() if "=" in v]

                f.write(f"\n[{group_name}]\n")
                for h in sorted(hostnames):
                    f.write(h + "\n")

                if group_vars:
                    f.write(f"\n[{group_name}:vars]\n")
                    for var in group_vars:
                        f.write(var + "\n")

        _, playbook_path = resolve_repo_path(filename, PLAYBOOKS_DIR)

        if playbook_path is None:
            raise ValueError("Invalid playbook path")

        if not os.path.isfile(playbook_path):
            raise FileNotFoundError(f"Playbook not found: {filename}")

        args = [ansible, playbook_path, '-i', temp_inventory] + secret_args

        if extra_vars_str:
            fd, temp_extra_vars = tempfile.mkstemp(prefix="netpac_extra_vars_", suffix=".json")
            with os.fdopen(fd, "w") as f:
                f.write(extra_vars_str)
            args += ['-e', f"@{temp_extra_vars}"]

        if dry_run:
            args += ['--check', '--diff']

        playbook_dir = os.path.dirname(playbook_path)

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
        if temp_extra_vars and os.path.exists(temp_extra_vars):
            os.remove(temp_extra_vars)
        remove_temp_files(temp_files)

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

        notify_job_finished(job_id)


# --------------------
#   Ansible Collections
# --------------------
ANSIBLE_GALAXY = shutil.which("ansible-galaxy") or "/usr/bin/ansible-galaxy"

@app.route("/ansible_collections")
@login_required
def ansible_collections():
    """Lists installed Ansible collections."""

    collections = []
    system_collections = []

    result = subprocess.run(
        [ANSIBLE_GALAXY, 'collection', 'list', '--format', 'json'],
        capture_output=True, text=True,
        env=tool_env()
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
    """Installs an Ansible collection."""

    collection = request.form.get("collection", "").strip()

    if not collection:
        flash("Collection name required", "danger")
        return redirect(url_for("ansible_collections"))

    if not COLLECTION_INSTALL_RE.match(collection):
        flash("Invalid collection name (expected namespace.name, optionally namespace.name:version)", "danger")
        return redirect(url_for("ansible_collections"))

    result = subprocess.run(
        [ANSIBLE_GALAXY, 'collection', 'install', collection],
        capture_output=True, text=True,
        env=tool_env()
    )

    if result.returncode == 0:
        logger.info(f"Ansible collection '{collection}' installed by {current_user.id}")
        audit("collection.install", collection)
        flash(f"Collection '{collection}' installed", "success")
    else:
        logger.error(f"Ansible collection '{collection}' install failed (by {current_user.id}): {sanitize_log(result.stderr)}")
        flash(f"Failed to install '{collection}': {result.stderr}", "danger")

    return redirect(url_for("ansible_collections"))


@app.route("/ansible_collections/uninstall", methods=["POST"])
@login_required
def ansible_collections_uninstall():
    """Removes a user-installed Ansible collection."""

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
        logger.info(f"Ansible collection '{collection}' removed by {current_user.id}")
        audit("collection.uninstall", collection)
        flash(f"Collection '{collection}' removed", "success")
    else:
        flash(f"Collection '{collection}' not found in user-installed collections (may be a system package)", "danger")

    return redirect(url_for("ansible_collections"))


@app.route("/ansible_collections/update", methods=["POST"])
@login_required
def ansible_collections_update():
    """Updates an Ansible collection."""

    collection = request.form.get("collection", "").strip()

    if not COLLECTION_NAME_RE.match(collection):
        flash("Invalid collection name (expected namespace.name)", "danger")
        return redirect(url_for("ansible_collections"))

    netpac_home = pwd.getpwuid(os.getuid()).pw_dir
    env = tool_env(ANSIBLE_COLLECTIONS_PATH=f'{netpac_home}/.ansible/collections:/usr/lib/python3/dist-packages/ansible_collections')

    result = subprocess.run(
        [ANSIBLE_GALAXY, 'collection', 'install', collection, '--upgrade'],
        capture_output=True, text=True,
        env=env
    )

    if result.returncode == 0:
        logger.info(f"Ansible collection '{collection}' updated by {current_user.id}")
        audit("collection.update", collection)
        flash(f"Collection '{collection}' updated", "success")
    else:
        logger.error(f"Ansible collection '{collection}' update failed (by {current_user.id}): {sanitize_log(result.stderr)}")
        flash(f"Failed to update '{collection}': {result.stderr}", "danger")

    return redirect(url_for("ansible_collections"))


@app.route("/ansible_collections/update_all", methods=["POST"])
@login_required
def ansible_collections_update_all():
    """Updates all user-installed Ansible collections."""

    result = subprocess.run(
        [ANSIBLE_GALAXY, 'collection', 'list', '--format', 'json'],
        capture_output=True, text=True,
        env=tool_env()
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
                        env=tool_env()
                    )
                    count += 1
            logger.info(f"Ansible: {count} collections updated by {current_user.id}")
            audit("collection.update_all", None, f"{count} collections")
            flash(f"Updated {count} collections", "success")
        except Exception as e:
            logger.error(f"Ansible collection update failed (by {current_user.id}): {e}")
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
    """Job history with search and pagination."""

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
    """Details and output of one job."""

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
    
    hosts = parse_play_recap(job['output']) if job['job_type'] == 'ansible' and job['status'] != 'running' else []
    hosts.sort(key=lambda h: (-(h['failed'] + h['unreachable']), -h['changed'], h['host']))
    failed_hosts = [h['host'] for h in hosts if h['failed'] or h['unreachable']]

    return render_template("history_detail.html", job=job, hosts=hosts, failed_hosts=failed_hosts)


RECAP_LINE_RE = re.compile(
    r"^(?P<host>\S+)\s*:\s*ok=(?P<ok>\d+)\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)"
    r"\s+failed=(?P<failed>\d+)(?:\s+skipped=(?P<skipped>\d+))?(?:\s+rescued=(?P<rescued>\d+))?(?:\s+ignored=(?P<ignored>\d+))?"
)


def parse_play_recap(output):
    """Returns the per-host results from the PLAY RECAP of an Ansible output."""

    text = ANSI_ESCAPE_RE.sub("", output or "")
    start = text.rfind("PLAY RECAP")
    if start == -1:
        return []
    results = []
    for line in text[start:].splitlines()[1:]:
        match = RECAP_LINE_RE.match(line.strip())
        if match:
            values = match.groupdict()
            results.append({"host": values.pop("host"), **{k: int(v or 0) for k, v in values.items()}})
    return results


@app.route("/history/<int:job_id>/rerun_failed", methods=["POST"])
@login_required
def rerun_failed_hosts(job_id):
    """Starts the playbook of a job again, limited to the hosts that failed or were unreachable."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT script_name, variables, credential, job_type, ansible_dry_run, status, output
            FROM history_jobs WHERE job_id = %s
        """, (job_id,))
        row = cur.fetchone()
    finally:
        cur.close()
        conn.close()

    if not row:
        abort(404)

    script_name, variables_raw, credential, job_type, dry_run, status, output = row
    if job_type != 'ansible' or status in ('running', 'planned'):
        flash("Only finished playbook jobs can be re-run for failed hosts", "warning")
        return redirect(url_for("history_detail", job_id=job_id))

    variables = json.loads(variables_raw) if variables_raw else {}
    if variables.get("redacted_fields"):
        flash("This job used password fields, which are not stored — launch the template again instead", "warning")
        return redirect(url_for("history_detail", job_id=job_id))

    failed_hosts = [h['host'] for h in parse_play_recap(output) if h['failed'] or h['unreachable']]
    if not failed_hosts:
        flash("This job has no failed or unreachable hosts", "warning")
        return redirect(url_for("history_detail", job_id=job_id))

    target = ",".join(failed_hosts)
    extra_vars = variables.get("extra_vars") or {}
    new_job_id = enqueue_job(script_name, current_user.id, target, json.dumps({**variables, "rerun_of": job_id}),
                             credential, 'ansible', {"extra_vars": json.dumps(extra_vars) if extra_vars else ""}, dry_run)

    exec_logger.info(f"Playbook '{sanitize_log(script_name)}' re-run for failed hosts of job #{job_id} queued as job #{new_job_id} by {current_user.id}")
    audit("job.rerun_failed", script_name, f"job #{new_job_id} from #{job_id}: {target}")
    flash(f"Re-run of {len(failed_hosts)} failed host(s) queued as job #{new_job_id}", "success")
    return redirect(url_for("history_detail", job_id=new_job_id))


@app.route("/history/<int:job_id>/status")
@login_required
def history_job_status(job_id):
    """Returns status and output of a job as JSON (live view)."""

    reap_stale_jobs_throttled()

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
    """Stops a running job or removes a queued one from the queue."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT status, pid FROM history_jobs WHERE job_id = %s", (job_id,))
        row = cur.fetchone()
        if not row:
            abort(404)

        status, pid = row
        if status == 'planned':
            cur.execute("""
                UPDATE history_jobs SET status = 'cancelled', finished_at = NOW(), duration = 0, run_payload = NULL,
                    output = CONCAT(COALESCE(output, ''), %s)
                WHERE job_id = %s AND status = 'planned'
            """, (JOB_CANCELLED_NOTE, job_id))
            conn.commit()
            if cur.rowcount == 1:
                notify_job_finished(job_id)
                exec_logger.info(f"Queued job {job_id} cancelled by {current_user.id}")
                audit("job.cancel", f"job #{job_id}", "while queued")
                flash(f"Job #{job_id} removed from the queue", "success")
            else:
                flash(f"Job #{job_id} has just been started — cancel it again to stop it", "warning")
            return redirect(url_for("history_detail", job_id=job_id))

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
            exec_logger.error(f"No permission to cancel job {job_id} (PID {pid})")
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
        notify_job_finished(job_id)

        exec_logger.info(f"Job {job_id} (PID {pid}) cancelled by {current_user.id}")
        audit("job.cancel", f"job #{job_id}")
        flash(f"Job #{job_id} cancelled", "success")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("history_detail", job_id=job_id))


# --------------------
#   Export history output as txt  
# --------------------
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


@app.route('/export_history_txt/<int:job_id>')
@login_required
def export_history_txt(job_id):
    """Downloads the output of a job as a text file."""

    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("SELECT script_name, output FROM history_jobs WHERE job_id = %s", (job_id,))
    row = cur.fetchone()
    
    cur.close()
    conn.close()
    
    if not row:
        abort(404)
    
    script_name, output = row
    
    output = ANSI_ESCAPE_RE.sub("", output or "") or "No output available."
    
    name = secure_filename(script_name)
    safe_name = name.replace(".py", "")
    filename = f"{safe_name}_{job_id}.txt"

    response = make_response(output)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


# ---------------------
#   Audit log
# ---------------------
AUDIT_PAGE_SIZE = 100
AUDIT_EXPORT_LIMIT = 50000


def audit_filters(args):
    """Returns (where clause, params, filter values) for the audit log filters."""

    values = {key: args.get(key, "").strip() for key in ("user", "action", "search", "date_from", "date_to")}
    where, params = [], []
    if values["user"]:
        where.append("username = %s")
        params.append(values["user"])
    if values["action"]:
        where.append("action LIKE %s")
        params.append(values["action"] + "%")
    if values["search"]:
        where.append("(target LIKE %s OR details LIKE %s OR ip LIKE %s)")
        params += [f"%{values['search']}%"] * 3
    for key, op in (("date_from", ">="), ("date_to", "<")):
        if values[key]:
            try:
                day = datetime.strptime(values[key], "%Y-%m-%d")
            except ValueError:
                values[key] = ""
                continue
            where.append(f"created_at {op} %s")
            params.append(day + timedelta(days=1) if key == "date_to" else day)
    return ("WHERE " + " AND ".join(where)) if where else "", params, values


@app.route("/audit")
@login_required
def audit_log_page():
    """Audit log with filters and pagination."""

    page = max(1, request.args.get("page", 1, type=int))
    where, params, filters = audit_filters(request.args)

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT COUNT(*) FROM audit_log {where}", params)
        total = cur.fetchone()[0]
        cur.execute(f"""
            SELECT created_at, username, ip, action, target, details FROM audit_log {where}
            ORDER BY id DESC LIMIT %s OFFSET %s
        """, params + [AUDIT_PAGE_SIZE, (page - 1) * AUDIT_PAGE_SIZE])
        entries = [dict(zip(["created_at", "username", "ip", "action", "target", "details"], row)) for row in cur.fetchall()]
        cur.execute("SELECT DISTINCT username FROM audit_log ORDER BY username")
        users = [row[0] for row in cur.fetchall()]
        cur.execute("SELECT DISTINCT SUBSTRING_INDEX(action, '.', 1) FROM audit_log ORDER BY 1")
        action_groups = [row[0] for row in cur.fetchall()]
    finally:
        cur.close()
        conn.close()

    return render_template("audit.html", entries=entries, total=total, page=page,
                           total_pages=max(1, (total + AUDIT_PAGE_SIZE - 1) // AUDIT_PAGE_SIZE),
                           filters=filters, users=users, action_groups=action_groups,
                           retention_days=AUDIT_RETENTION_DAYS)


@app.route("/audit/export")
@login_required
def export_audit_csv():
    """Downloads the filtered audit log as CSV."""

    where, params, _ = audit_filters(request.args)
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(f"""
            SELECT created_at, username, ip, action, target, details FROM audit_log {where}
            ORDER BY id DESC LIMIT %s
        """, params + [AUDIT_EXPORT_LIMIT])
        rows = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["time", "user", "ip", "action", "target", "details"])
    for row in rows:
        writer.writerow([row[0].strftime("%Y-%m-%d %H:%M:%S")] + [value if value is not None else "" for value in row[1:]])

    audit("audit.export", None, f"{len(rows)} entries")
    response = make_response(buffer.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = f"attachment; filename=netpac_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return response


# ---------------------
#   Schedule
# ---------------------
@app.route("/schedule")
@login_required
def schedule():
    """Lists all schedules with the form for new ones."""

    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM schedule_jobs ORDER BY created_at DESC")
    jobs = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("schedule.html", jobs=jobs, secrets=load_secret_choices(),
                           scripts=list_repo_files(SCRIPTS_DIR, ('.py',)),
                           playbooks=list_repo_files(PLAYBOOKS_DIR, PLAYBOOK_EXTENSIONS))


@app.route("/schedule/add", methods=["POST"])
@login_required
def add_schedule():
    """Creates a schedule and registers it in the scheduler."""

    job_type = request.form.get("job_type", "python").strip()
    script_name = request.form.get("script_name", "").strip()
    target = request.form.get("target", "").strip()
    schedule_type = request.form.get("schedule_type", "").strip()
    secret_1 = request.form.get("secret_1", "").strip()
    secret_2 = request.form.get("secret_2", "").strip()
    secret_3 = request.form.get("secret_3", "").strip()

    if job_type not in ("python", "ansible"):
        flash("Invalid job type", "danger")
        return redirect(url_for("schedule"))

    if job_type == "ansible":
        target, error = parse_playbook_target(request.form)
        if error:
            flash(error, "danger")
            return redirect(url_for("schedule"))

    if job_type == "ansible":
        extra_vars = parse_extra_vars(request.form.get("extra_vars_raw", ""))
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

        register_schedule_job(cron_id, script_name, current_user.id, target, variables,
                              secrets_json, use_venv, job_type, schedule)
        conn.commit()
        logger.info(f"Schedule #{cron_id} ({sanitize_log(script_name)}, '{schedule}') added by {current_user.id}")
        audit("schedule.create", script_name, f"#{cron_id}, {schedule}")
        flash("Schedule added", "success")

    except Exception as e:
        logger.error(f"Error adding schedule: {e}")
        conn.rollback()
        flash("Error adding schedule", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("schedule"))


@app.route("/schedule/toggle/<int:cron_id>", methods=["POST"])
@login_required
def toggle_schedule(cron_id):
    """Activates or deactivates a schedule."""

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
            cur.execute(f"SELECT {SCHEDULE_JOB_COLUMNS} FROM schedule_jobs WHERE job_id = %s", (cron_id,))
            register_schedule_job(*cur.fetchone())
        else:
            try:
                scheduler.remove_job(str(cron_id))
                scheduler_logger.info(f"Job {cron_id} removed from scheduler")
            except Exception as e:
                scheduler_logger.error(f"Could not remove job {cron_id}: {e}")

        logger.info(f"Schedule #{cron_id} {'activated' if new_status else 'deactivated'} by {current_user.id}")
        audit("schedule.toggle", f"#{cron_id}", "activated" if new_status else "deactivated")
        flash("Schedule updated", "success")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling schedule {cron_id}: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("schedule"))


@app.route("/schedule/delete/<int:cron_id>", methods=["POST"])
@login_required
def delete_schedule(cron_id):
    """Deletes a schedule."""

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("DELETE FROM schedule_jobs WHERE job_id = %s", (cron_id,))
        conn.commit()

        try:
            scheduler.remove_job(str(cron_id))
        except Exception:
            pass

        logger.info(f"Schedule #{cron_id} deleted by {current_user.id}")
        audit("schedule.delete", f"#{cron_id}")
        flash("Schedule deleted", "success")

    except Exception as e:
        logger.error(f"Error deleting schedule {cron_id}: {e}")
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
    """Settings page with all tabs."""

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

    notification_config = load_notification_settings()
    notification_rules = load_notification_rules()

    return render_template("settings.html", logs=log_files, git_config=git_config,
                        user_method=user_method, users=users, backups=backup_files,
                        active_tab=active_tab, radius_config=radius_config, ssl_info=ssl_info_data,
                        notification_config=notification_config, notification_rules=notification_rules,
                        notify_statuses=NOTIFY_STATUSES)


@app.route("/settings/git", methods=["POST"])
@login_required
def save_git_config():
    """Saves the Git repository settings."""

    repo_url     = request.form.get("repo_url", "").strip()
    branch       = request.form.get("branch", "main").strip()
    token_input  = request.form.get("access_token", "").strip()

    if not repo_url:
        flash("The repo URL cannot be empty", "danger")
        return redirect(url_for("settings", tab="git"))

    if not repo_url.startswith("https://"):
        flash("The URL must begin with https://", "danger")
        return redirect(url_for("settings", tab="git"))

    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9_\-/.]*\Z', branch):
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
        audit("git.config_save", repo_url, f"branch: {branch}")
        flash("Git config saved!", "success")
    except Exception as e:
        logger.error(f"Error saving git config: {e}")
        flash("Error saving git config", "danger")

    return redirect(url_for("settings", tab="git"))


@app.route("/settings/logs/<filename>")
@login_required
def view_log(filename):
    """Shows the last 50 lines of a log file."""

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
    """Changes the password of the logged-in local user."""

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

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
        remember_auth_state(current_user.id)
        flash("Password changed successfully — all other sessions have been logged out", "success")
        logger.info(f"Password changed for user: {current_user.id}")
        audit("user.password_change", current_user.id)

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
    """Creates a local user (admin only)."""

    if current_user.id != 'admin':
        abort(403)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    method = "local"

    if not username or not password:
        flash("Username and password are required", "danger")
        return redirect(url_for("settings", tab="user"))

    if len(username) > MAX_USERNAME_LENGTH:
        flash(f"Username is too long (max. {MAX_USERNAME_LENGTH} characters)", "danger")
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
        audit("user.create", username)

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
    """Deletes a user (admin only)."""

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
        audit("user.delete", username)

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
    """Saves the RADIUS settings (admin only)."""

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
        audit("radius.config_save", server_host)
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
    """Tests the RADIUS settings with a login attempt (admin only)."""

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
        srv = make_radius_client(server_host, server_port, radius_secret, timeout)

        req = srv.CreateAuthPacket(
            code=pyrad.packet.AccessRequest,
            User_Name=test_username,
            NAS_Identifier="NetPAC"
        )
        req["User-Password"] = req.PwCrypt(test_password)
        req.add_message_authenticator()
        reply = srv.SendPacket(req)

        if not radius_reply_is_authentic(req, reply, radius_secret):
            logger.error(f"RADIUS test failed: {RADIUS_MA_MISSING_HINT}")
            return jsonify({"success": False, "message": RADIUS_MA_MISSING_HINT})

        if reply.code == pyrad.packet.AccessAccept:
            logger.info(f"RADIUS test successful for user '{sanitize_log(test_username)}' by {current_user.id}")
            audit("radius.test", test_username, "Access-Accept")
            return jsonify({"success": True, "message": f"Access-Accept received for '{test_username}'"})
        else:
            return jsonify({"success": False, "message": f"Access-Reject received for '{test_username}'"})

    except RadiusTimeout:
        logger.error(f"RADIUS test failed: {RADIUS_TIMEOUT_HINT}")
        return jsonify({"success": False, "message": RADIUS_TIMEOUT_HINT}), 504
    except Exception as e:
        logger.error(f"RADIUS test failed: Error: {e!r}")
        return jsonify({"success": False, "message": f"Error: {e!r}"}), 500


# --------------------
#   Notification settings & rules
# --------------------
def load_notification_rules():
    """Loads all notification rules."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT rule_id, name, channel, target, on_completed, on_failed, on_timeout, on_cancelled,
                   job_type, is_active, created_by
            FROM notification_rules ORDER BY name
        """)
        keys = ['rule_id', 'name', 'channel', 'target', 'on_completed', 'on_failed', 'on_timeout',
                'on_cancelled', 'job_type', 'is_active', 'created_by']
        return [dict(zip(keys, row)) for row in cur.fetchall()]
    except Exception as e:
        logger.error(f"Could not load notification rules: {e}")
        return []
    finally:
        cur.close()
        conn.close()


def parse_notification_rule_form():
    """Returns (rule data, error) from the rule form."""

    name = request.form.get("name", "").strip()
    channel = request.form.get("channel", "").strip()
    target = request.form.get("target", "").strip()
    type_python = bool(request.form.get("type_python"))
    type_ansible = bool(request.form.get("type_ansible"))
    job_type = "all" if type_python and type_ansible else "python" if type_python else "ansible" if type_ansible else None
    statuses = {s: 1 if request.form.get(f"on_{s}") else 0 for s in NOTIFY_STATUSES}
    is_active = 1 if request.form.get("is_active") else 0

    if not name or len(name) > 100:
        return None, "Name is required (max. 100 characters)"
    if channel not in NOTIFY_CHANNELS:
        return None, "Invalid notification channel"
    if channel == 'email' and not NOTIFY_EMAIL_RE.match(target):
        return None, "Please enter a valid e-mail address"
    if channel == 'matrix' and not NOTIFY_MATRIX_ROOM_RE.match(target):
        return None, "Please enter a valid Matrix room ID starting with ! (e.g. !abc123 or !abc123:<homeserver>)"
    if len(target) > 255:
        return None, "Target is too long (max. 255 characters)"
    if job_type not in NOTIFY_JOB_TYPES:
        return None, "Select Python scripts, Ansible playbooks or both"
    if not any(statuses.values()):
        return None, "Select at least one status to notify on"

    return {
        'name': name, 'channel': channel, 'target': target, 'job_type': job_type,
        'is_active': is_active, **{f"on_{s}": v for s, v in statuses.items()}
    }, None


@app.route("/settings/notifications", methods=["POST"])
@login_required
def save_notification_settings():
    """Saves the SMTP and Matrix settings."""

    smtp_host = request.form.get("smtp_host", "").strip()
    smtp_port = request.form.get("smtp_port", "587").strip() or "587"
    smtp_security = request.form.get("smtp_security", "starttls").strip()
    smtp_user = request.form.get("smtp_user", "").strip()
    smtp_password = request.form.get("smtp_password", "")
    smtp_from = request.form.get("smtp_from", "").strip()
    matrix_homeserver = request.form.get("matrix_homeserver", "").strip()
    matrix_token = request.form.get("matrix_token", "").strip()
    base_url = request.form.get("notify_base_url", "").strip()

    try:
        smtp_port = int(smtp_port)
    except ValueError:
        flash("SMTP port must be a number", "danger")
        return redirect(url_for("settings", tab="notifications"))

    if smtp_security not in NOTIFY_SMTP_SECURITY:
        flash("Invalid SMTP security option", "danger")
        return redirect(url_for("settings", tab="notifications"))
    if smtp_from and not NOTIFY_EMAIL_RE.match(smtp_from):
        flash("Sender address is not a valid e-mail address", "danger")
        return redirect(url_for("settings", tab="notifications"))
    for label, url in (("Matrix homeserver", matrix_homeserver), ("Base URL", base_url)):
        if url and not url.startswith(("https://", "http://")):
            flash(f"{label} must start with https:// or http://", "danger")
            return redirect(url_for("settings", tab="notifications"))
    if (smtp_password or matrix_token) and not encryption.is_available():
        flash("ENCRYPTION_KEY is missing — passwords and tokens cannot be stored", "danger")
        return redirect(url_for("settings", tab="notifications"))

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT smtp_encrypted_password, matrix_encrypted_token FROM notification_settings WHERE id = 1")
        existing = cur.fetchone() or (None, None)

        smtp_pw_enc = encryption.encrypt(smtp_password) if smtp_password else existing[0]
        matrix_token_enc = encryption.encrypt(matrix_token) if matrix_token else existing[1]

        cur.execute("""
            INSERT INTO notification_settings
                (id, smtp_host, smtp_port, smtp_security, smtp_user, smtp_encrypted_password, smtp_from,
                 matrix_homeserver, matrix_encrypted_token, base_url)
            VALUES (1, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                smtp_host = VALUES(smtp_host),
                smtp_port = VALUES(smtp_port),
                smtp_security = VALUES(smtp_security),
                smtp_user = VALUES(smtp_user),
                smtp_encrypted_password = VALUES(smtp_encrypted_password),
                smtp_from = VALUES(smtp_from),
                matrix_homeserver = VALUES(matrix_homeserver),
                matrix_encrypted_token = VALUES(matrix_encrypted_token),
                base_url = VALUES(base_url)
        """, (smtp_host, smtp_port, smtp_security, smtp_user, smtp_pw_enc, smtp_from,
              matrix_homeserver, matrix_token_enc, base_url))
        conn.commit()
        logger.info(f"Notification settings updated by {current_user.id}")
        audit("notification.settings_save")
        flash("Notification settings saved", "success")
    except Exception as e:
        logger.error(f"Error saving notification settings: {e}")
        conn.rollback()
        flash("Error saving notification settings", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("settings", tab="notifications"))


@app.route("/settings/notifications/rules", methods=["POST"])
@login_required
def create_notification_rule():
    """Creates a notification rule."""

    data, error = parse_notification_rule_form()
    if error:
        flash(error, "danger")
        return redirect(url_for("settings", tab="notifications"))

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO notification_rules
                (name, channel, target, on_completed, on_failed, on_timeout, on_cancelled, job_type, is_active, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (data['name'], data['channel'], data['target'], data['on_completed'], data['on_failed'],
              data['on_timeout'], data['on_cancelled'], data['job_type'], data['is_active'], current_user.id))
        conn.commit()
        logger.info(f"Notification rule '{sanitize_log(data['name'])}' created by {current_user.id}")
        audit("notification.rule_create", data["name"], f"{data['channel']}: {data['target']}")
        flash(f"Notification rule '{data['name']}' created", "success")
    except Exception as e:
        logger.error(f"Error creating notification rule: {e}")
        conn.rollback()
        flash("Error creating notification rule", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("settings", tab="notifications"))


@app.route("/settings/notifications/rules/edit/<int:rule_id>", methods=["POST"])
@login_required
def edit_notification_rule(rule_id):
    """Updates a notification rule."""

    data, error = parse_notification_rule_form()
    if error:
        flash(error, "danger")
        return redirect(url_for("settings", tab="notifications"))

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT 1 FROM notification_rules WHERE rule_id = %s", (rule_id,))
        if not cur.fetchone():
            flash("Notification rule not found", "danger")
            return redirect(url_for("settings", tab="notifications"))

        cur.execute("""
            UPDATE notification_rules
            SET name = %s, channel = %s, target = %s, on_completed = %s, on_failed = %s,
                on_timeout = %s, on_cancelled = %s, job_type = %s, is_active = %s
            WHERE rule_id = %s
        """, (data['name'], data['channel'], data['target'], data['on_completed'], data['on_failed'],
              data['on_timeout'], data['on_cancelled'], data['job_type'], data['is_active'], rule_id))
        conn.commit()
        logger.info(f"Notification rule {rule_id} ('{sanitize_log(data['name'])}') updated by {current_user.id}")
        audit("notification.rule_update", data["name"], f"{data['channel']}: {data['target']}")
        flash(f"Notification rule '{data['name']}' updated", "success")
    except Exception as e:
        logger.error(f"Error updating notification rule {rule_id}: {e}")
        conn.rollback()
        flash("Error updating notification rule", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("settings", tab="notifications"))


@app.route("/settings/notifications/rules/toggle/<int:rule_id>", methods=["POST"])
@login_required
def toggle_notification_rule(rule_id):
    """Activates or deactivates a notification rule."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE notification_rules SET is_active = NOT is_active WHERE rule_id = %s", (rule_id,))
        conn.commit()
        if cur.rowcount == 0:
            flash("Notification rule not found", "danger")
        else:
            logger.info(f"Notification rule {rule_id} toggled by {current_user.id}")
            audit("notification.rule_toggle", f"#{rule_id}")
    except Exception as e:
        logger.error(f"Error toggling notification rule {rule_id}: {e}")
        conn.rollback()
        flash("Error toggling notification rule", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("settings", tab="notifications"))


@app.route("/settings/notifications/rules/delete/<int:rule_id>", methods=["POST"])
@login_required
def delete_notification_rule(rule_id):
    """Deletes a notification rule."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM notification_rules WHERE rule_id = %s", (rule_id,))
        conn.commit()
        if cur.rowcount == 0:
            flash("Notification rule not found", "danger")
        else:
            logger.info(f"Notification rule {rule_id} deleted by {current_user.id}")
            audit("notification.rule_delete", f"#{rule_id}")
            flash("Notification rule deleted", "success")
    except Exception as e:
        logger.error(f"Error deleting notification rule {rule_id}: {e}")
        conn.rollback()
        flash("Error deleting notification rule", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("settings", tab="notifications"))


@app.route("/settings/notifications/rules/test/<int:rule_id>", methods=["POST"])
@limiter.limit("5 per minute", methods=["POST"])
@login_required
def test_notification_rule(rule_id):
    """Sends a test notification for a rule."""

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT name, channel, target FROM notification_rules WHERE rule_id = %s", (rule_id,))
        row = cur.fetchone()
    finally:
        cur.close()
        conn.close()

    if not row:
        abort(404)

    name, channel, target = row
    cfg = load_notification_settings(with_secrets=True)
    subject = "[NetPAC] Test notification"
    body = f"This is a test notification from NetPAC for rule '{name}', sent by {current_user.id}."
    html_body = f"<b>NetPAC test notification</b><br>Rule <b>{Markup.escape(name)}</b>, sent by {Markup.escape(current_user.id)}."

    try:
        send_notification(cfg, channel, target, subject, body, html_body, f"netpac-test-{uuid.uuid4().hex}")
        logger.info(f"Test notification for rule {rule_id} ({channel}) sent by {current_user.id}")
        audit("notification.rule_test", name, f"{channel}: {target}")
        flash(f"Test notification sent to {target}", "success")
    except Exception as e:
        logger.error(f"Test notification for rule {rule_id} ({channel}) failed: {sanitize_log(repr(e))}")
        flash(f"Test notification failed: {e}", "danger")

    return redirect(url_for("settings", tab="notifications"))

# ---------------------
#   SSL Certs
# ---------------------
def get_ssl_info():
    """Returns subject, issuer and expiry of the installed certificate."""

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
                "not_valid_after": getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after,
                "is_self_signed": cert.subject == cert.issuer
            }
        except Exception as e:
            logger.error(f"Failed to read SSL cert info: {e}")

    return info


@app.route("/settings/ssl/upload", methods=["POST"])
@login_required
def upload_ssl_cert():
    """Replaces the TLS certificate and key (admin only)."""

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
        audit("ssl.upload")
        flash("Certificate uploaded successfully. Restart nginx to apply: sudo systemctl reload nginx", "success")

    except Exception as e:
        logger.error(f"SSL upload error: {e}")
        flash(f"Error saving certificate: {str(e)}", "danger")

    return redirect(url_for("settings", tab="ssl"))


# ---------------------
#   Server error route
# ---------------------
ERROR_MESSAGES = {
    400: "Invalid Request",
    403: "Access Denied",
    404: "Page Not Found",
    405: "Method Not Allowed",
    429: "Too Many Requests — please wait a moment",
    500: "Internal Server Error",
}


def request_log_context():
    """Returns method, URL, IP and user of the request for log lines."""

    try:
        user = current_user.id if current_user and current_user.is_authenticated else "-"
    except Exception:
        user = "?"
    return f"{request.method} {sanitize_log(request.url)} (IP: {get_real_ip()}, user: {user})"


@app.errorhandler(Exception)
def handle_error(e):
    """Logs an error in one line and shows the error page."""

    if isinstance(e, HTTPException):
        error_code = e.code or 500
        logger.warning(f"HTTP {error_code}: {request_log_context()}")
    else:
        error_code = 500
        frame = traceback.extract_tb(e.__traceback__)[-1] if e.__traceback__ else None
        location = f" at {os.path.basename(frame.filename)}:{frame.lineno} in {frame.name}()" if frame else ""
        logger.error(f"Unhandled {type(e).__name__}{location}: {sanitize_log(str(e))} — {request_log_context()}")

    return render_template("error.html",
                           error_code=error_code,
                           error_message=ERROR_MESSAGES.get(error_code, "An error has occurred")), error_code


# ---------------------
#   Secrets
# ---------------------
def find_secret_usages(cur, secret_name):
    """Lists schedules and templates that use a secret."""

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

SECRET_TYPES = {"password": "Password", "ssh_key": "SSH key", "vault_password": "Vault password"}


def normalize_private_key(text):
    """Normalizes line endings of a pasted private key; ssh needs a trailing newline."""

    return text.replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"


def load_private_key(text, passphrase=None):
    """Loads an OpenSSH or PEM private key; raises ValueError if it is invalid or the passphrase is wrong."""

    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization

    data = text.encode()
    password = passphrase.encode() if passphrase else None
    for loader in (serialization.load_ssh_private_key, serialization.load_pem_private_key):
        try:
            return loader(data, password=password)
        except (ValueError, TypeError):
            continue
        except UnsupportedAlgorithm as e:
            raise ValueError(f"This key type can't be read on the server ({e}) — for passphrase-protected OpenSSH keys "
                             "the Python package bcrypt is required")
    raise ValueError("Invalid private key or wrong passphrase")


def unencrypted_private_key(text, passphrase=None):
    """Returns the key in OpenSSH format without passphrase, as ssh can't ask for it in a background job."""

    from cryptography.hazmat.primitives import serialization

    if not passphrase:
        return normalize_private_key(text)
    key = load_private_key(text, passphrase)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                             serialization.NoEncryption()).decode()


def write_private_file(content, prefix, temp_files):
    """Writes content to a temporary file only the NetPAC user can read and remembers it for cleanup."""

    fd, file_path = tempfile.mkstemp(prefix=prefix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    temp_files.append(file_path)
    return file_path


def remove_temp_files(temp_files):
    """Deletes the temporary key and vault files of a job."""

    for file_path in temp_files:
        try:
            os.remove(file_path)
        except OSError:
            pass


def prepare_job_secrets(cur, secret_names, env, temp_files):
    """Loads the selected secrets into the job environment and returns the matching Ansible arguments."""

    ansible_args = []
    key_passed = False
    for num, name in enumerate(secret_names, 1):
        if not name:
            continue
        cur.execute("SELECT secret_type, username, encrypted_password, encrypted_passphrase FROM secrets WHERE name = %s", (name,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Secret '{name}' not found (deleted or renamed?)")

        secret_type, username, value_enc, passphrase_enc = row
        value = encryption.decrypt(value_enc)
        env[f"SECRET_{num}_TYPE"] = secret_type
        env[f"SECRET_{num}_USERNAME"] = username or ""

        if secret_type == "ssh_key":
            passphrase = encryption.decrypt(passphrase_enc) if passphrase_enc else None
            key_file = write_private_file(unencrypted_private_key(value, passphrase), "netpac_key_", temp_files)
            env[f"SECRET_{num}_KEYFILE"] = key_file
            if not key_passed:
                ansible_args += ["--private-key", key_file] + (["--user", username] if username else [])
                key_passed = True
        elif secret_type == "vault_password":
            vault_file = write_private_file(value, "netpac_vault_", temp_files)
            env[f"SECRET_{num}_VAULTFILE"] = vault_file
            ansible_args += ["--vault-id", f"{re.sub(r'[^A-Za-z0-9_.-]', '_', name)}@{vault_file}"]
        else:
            env[f"SECRET_{num}_PASSWORD"] = value
    return ansible_args


def parse_secret_form(form, existing=None):
    """Returns (data, error) for the secret form; existing holds the stored secret when editing."""

    secret_type = form.get("secret_type", "password")
    name = form.get("name", "").strip()
    username = form.get("username", "").strip()
    description = form.get("description", "").strip()
    value = normalize_private_key(form.get("private_key", "")) if secret_type == "ssh_key" and form.get("private_key", "").strip() \
        else (form.get("password", "") if secret_type != "ssh_key" else "")
    passphrase = form.get("passphrase", "") if secret_type == "ssh_key" else ""

    if secret_type not in SECRET_TYPES:
        return None, "Invalid secret type"
    if not name or len(name) > 100:
        return None, "Name is required (max. 100 characters)"
    if secret_type == "vault_password":
        username = ""
    elif not username:
        return None, "Username is required"
    if len(username) > 100:
        return None, "Username is too long (max. 100 characters)"

    type_changed = existing is not None and existing["secret_type"] != secret_type
    if not value and (existing is None or type_changed):
        return None, "Please enter the private key" if secret_type == "ssh_key" else "Please enter the password"

    data = {"name": name, "secret_type": secret_type, "username": username, "description": description,
            "value": value or None, "passphrase": None, "passphrase_changed": False}

    if secret_type == "ssh_key":
        if value:
            key_text, key_passphrase = value, passphrase or None
            data["passphrase"], data["passphrase_changed"] = key_passphrase, True
        else:
            key_text = encryption.decrypt(existing["encrypted_password"])
            if passphrase:
                key_passphrase = passphrase
                data["passphrase"], data["passphrase_changed"] = passphrase, True
            else:
                key_passphrase = encryption.decrypt(existing["encrypted_passphrase"]) if existing["encrypted_passphrase"] else None
        try:
            load_private_key(key_text, key_passphrase)
        except ValueError as e:
            return None, str(e)
    elif existing is not None and existing["secret_type"] == "ssh_key":
        data["passphrase_changed"] = True
    return data, None


@app.route("/secrets")
@login_required
def secrets():
    """Lists all secrets (without passwords)."""

    if not encryption.is_available():
        flash("The Secrets feature is not available. ENCRYPTION_KEY is missing or invalid.", "danger")
        return redirect(url_for("dashboard"))
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        sql_query = "SELECT id, name, username, description, created_at, secret_type FROM secrets ORDER BY created_at DESC"
        cur.execute(sql_query)
        all_secrets = cur.fetchall()
        
        secrets_list = []
        for row in all_secrets:
            secrets_list.append({
                'id': row[0],
                'name': row[1],
                'username': row[2],
                'description': row[3],
                'created_at': row[4],
                'secret_type': row[5]
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
    """Creates a secret."""

    if not encryption.is_available():
        flash("The Secrets feature is not available. ENCRYPTION_KEY is missing or invalid.", "danger")
        return redirect(url_for("secrets"))
    
    if request.method == "POST":
        data, error = parse_secret_form(request.form)
        if error:
            flash(error, "danger")
            return redirect(url_for("create_secret"))
        name = data["name"]

        conn = get_db()
        cur = conn.cursor()

        try:
            cur.execute("""
                INSERT INTO secrets (name, secret_type, username, encrypted_password, encrypted_passphrase, description)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (name, data["secret_type"], data["username"], encryption.encrypt(data["value"]),
                  encryption.encrypt(data["passphrase"]) if data["passphrase"] else None, data["description"]))
            conn.commit()

            logger.info(f"Secret '{sanitize_log(name)}' ({data['secret_type']}) created by {current_user.id}")
            audit("secret.create", name, SECRET_TYPES[data["secret_type"]])
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
    """Updates a secret (password only if a new one is entered)."""

    if not encryption.is_available():
        flash("The Secrets feature is not available. ENCRYPTION_KEY is missing or invalid.", "danger")
        return redirect(url_for("secrets"))
    
    conn = get_db()
    cur = conn.cursor()
    
    try:

        cur.execute("""
            SELECT id, name, username, description, secret_type, encrypted_password, encrypted_passphrase
            FROM secrets WHERE id = %s
        """, (secret_id,))
        row = cur.fetchone()
        
        if not row:
            flash("Secret not found", "danger")
            return redirect(url_for("secrets"))
        
        secret = {
            'id': row[0],
            'name': row[1],
            'username': row[2],
            'description': row[3],
            'secret_type': row[4],
            'has_passphrase': bool(row[6])
        }
        stored = {"secret_type": row[4], "encrypted_password": row[5], "encrypted_passphrase": row[6]}
        
        if request.method == "POST":
            data, error = parse_secret_form(request.form, stored)
            if error:
                flash(error, "danger")
                return render_template("edit_secret.html", secret=secret)
            name, new_password = data["name"], data["value"]

            try:
                fields = ["name = %s", "secret_type = %s", "username = %s", "description = %s"]
                values = [name, data["secret_type"], data["username"], data["description"]]
                if new_password:
                    fields.append("encrypted_password = %s")
                    values.append(encryption.encrypt(new_password))
                if data["passphrase_changed"]:
                    fields.append("encrypted_passphrase = %s")
                    values.append(encryption.encrypt(data["passphrase"]) if data["passphrase"] else None)
                cur.execute(f"UPDATE secrets SET {', '.join(fields)} WHERE id = %s", values + [secret_id])

                conn.commit()
                logger.info(f"Secret '{sanitize_log(name)}' (ID: {secret_id}) updated by {current_user.id}")
                audit("secret.update", name, f"{SECRET_TYPES[data['secret_type']]}" + (", value changed" if new_password else ""))
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
    """Deletes a secret."""

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
        
        logger.info(f"Secret '{sanitize_log(secret_name)}' (ID: {secret_id}) deleted by {current_user.id}")
        audit("secret.delete", secret_name)
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


def ensure_backup_dir():
    """Creates the backup folder and restricts it to the NetPAC user."""

    try:
        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
        os.chmod(BACKUP_DIR, 0o700)
        for path in glob.glob(os.path.join(BACKUP_DIR, "*.sql")):
            os.chmod(path, 0o600)
    except OSError as e:
        logger.error(f"Could not restrict permissions of {BACKUP_DIR}: {e}")


def open_private(path):
    """Opens a file for writing that only the owner can read (0600)."""

    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w")


ensure_backup_dir()


def run_backup_background(backup_type, filename, output_path, tables):
    """Creates a database backup with mysqldump."""

    mysqldump = shutil.which("mysqldump") or "/usr/bin/mysqldump"

    env = tool_env()

    try:
        with open_private(output_path) as f:
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
    """Starts a hosts or full backup (admin only)."""

    if current_user.id != 'admin':
        abort(403)

    backup_type = request.form.get("backup_type", "").strip()

    if backup_type not in ("hosts", "full"):
        flash("Invalid backup type", "danger")
        return redirect(url_for("settings", tab="backup"))

    ensure_backup_dir()

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
    audit("backup.create", filename, backup_type)
    flash(f"Backup '{filename}' is being created in the background — refresh in a moment to see it in the list", "success")

    return redirect(url_for("settings", tab="backup"))


@app.route("/settings/backup/download/<filename>")
@login_required
def download_backup(filename):
    """Downloads a backup file (admin only)."""

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

    audit("backup.download", safe_filename)
    return send_from_directory(backup_dir, safe_filename, as_attachment=True)


@app.route("/settings/backup/delete", methods=["POST"])
@login_required
def delete_backup():
    """Deletes a backup file (admin only)."""

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
            audit("backup.delete", safe_filename)
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
    """Restores a backup after password and TOTP check (admin only)."""

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
        audit("backup.restore_failed", safe_filename, "wrong password")
        flash("Incorrect password", "danger")
        return redirect(url_for("settings", tab="backup"))

    totp_secret, _ = decrypt_totp_secret(totp_secret)
    if not totp_secret or not totp_confirmed:
        flash("TOTP is not set up or not confirmed for this account — cannot verify restore", "danger")
        return redirect(url_for("settings", tab="backup"))

    conn = get_db()
    cur = conn.cursor()
    try:
        code_ok = consume_totp_code(cur, current_user.id, totp_secret, totp_code)
        conn.commit()
    finally:
        cur.close()
        conn.close()

    if not code_ok:
        logger.warning(f"Failed restore attempt by {current_user.id}: wrong TOTP code")
        audit("backup.restore_failed", safe_filename, "wrong TOTP code")
        flash("Incorrect or already used TOTP code — wait for the next code", "danger")
        return redirect(url_for("settings", tab="backup"))

    is_hosts_backup = "hosts_backup" in safe_filename
    tables = ["hosts", "host_groups", "host_group_membership"] if is_hosts_backup else None

    safety_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safety_filename = f"netpac_pre_restore_safety_{safety_timestamp}.sql"
    safety_path = os.path.join(BACKUP_DIR, safety_filename)

    mysqldump = shutil.which("mysqldump") or "/usr/bin/mysqldump"
    mysql_bin = shutil.which("mysql") or "/usr/bin/mysql"

    env = tool_env()
    ensure_backup_dir()

    try:
        with open_private(safety_path) as f:
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
        """Imports an SQL file; returns (ok, error)."""

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
        audit("backup.restore", safe_filename)
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
    """System health page (database, scheduler, venv, collections)."""

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
        result = subprocess.run(
            ['/usr/bin/systemctl', 'is-active', 'netpac-executor.service'],
            capture_output=True, text=True
        )
        executor_running = result.stdout.strip() == 'active'

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT status, COUNT(*) FROM history_jobs WHERE status IN ('running', 'planned') GROUP BY status")
        counts = dict(cur.fetchall())
        cur.close()
        conn.close()

        queue_info = f"Running: {counts.get('running', 0)} of max. {MAX_PARALLEL_JOBS} | Queued: {counts.get('planned', 0)}"
        checks['executor'] = {
            'status': 'ok' if executor_running else 'error',
            'message': queue_info if executor_running else f"netpac-executor.service is not running, no jobs are started | {queue_info}"
        }
    except Exception as e:
        checks['executor'] = {'status': 'error', 'message': str(e)}

    for key, folder, extensions in (('scripts_dir', SCRIPTS_DIR, ('.py',)), ('playbooks_dir', PLAYBOOKS_DIR, PLAYBOOK_EXTENSIONS)):
        if not os.path.isdir(folder):
            checks[key] = {'status': 'error', 'message': f"{folder} does not exist — run setup.sh again"}
        elif not os.access(folder, os.W_OK | os.X_OK):
            checks[key] = {'status': 'error', 'message': f"{folder} is not writable for the NetPAC user"}
        else:
            count = len([f for f in list_repo_files(folder, extensions) if not f.startswith("git/")])
            checks[key] = {'status': 'ok', 'message': f"{folder} · {count} {'file' if count == 1 else 'files'}"}

    git_config = load_git_config()
    if not git_config.get("repo_url"):
        checks['git'] = {'status': 'ok', 'message': "No repository configured"}
    elif not os.path.isdir(os.path.join(GIT_DIR, ".git")):
        checks['git'] = {'status': 'error', 'message': f"{git_config['repo_url']} is configured but not synced yet"}
    else:
        marker = os.path.join(GIT_DIR, ".git", "FETCH_HEAD")
        if not os.path.exists(marker):
            marker = os.path.join(GIT_DIR, ".git", "HEAD")
        synced = datetime.fromtimestamp(os.path.getmtime(marker)).strftime('%Y-%m-%d %H:%M')
        checks['git'] = {'status': 'ok', 'message': f"{git_config['repo_url']} @ {git_config.get('branch', 'main')} · last sync {synced}"}

    try:
        ansible = shutil.which("ansible-playbook")
        if not ansible:
            checks['ansible'] = {'status': 'error', 'message': 'ansible-playbook not found in PATH'}
        else:
            result = subprocess.run([ansible, '--version'], capture_output=True, text=True, timeout=15, env=tool_env())
            first_line = (result.stdout or result.stderr).strip().splitlines()[0] if (result.stdout or result.stderr).strip() else ""
            checks['ansible'] = {
                'status': 'ok' if result.returncode == 0 else 'error',
                'version': first_line.replace("ansible-playbook", "ansible-core").replace("[core ", "").rstrip("]") or "unknown version"
            }
    except Exception as e:
        checks['ansible'] = {'status': 'error', 'message': str(e)}

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
        env = tool_env()
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

    order = ['mariadb', 'sql-size', 'encryption', 'scheduler', 'executor', 'python', 'venv', 'ansible', 'ansible_galaxy',
             'scripts_dir', 'playbooks_dir', 'git']
    checks = {key: checks[key] for key in order if key in checks}

    overall = 'ok' if all(c['status'] == 'ok' for c in checks.values()) else 'error'
    
    return render_template("health.html", checks=checks, overall=overall)


# ---------------------
#   Default checks
# ---------------------
@app.before_request
def check_default_password():
    """Warns the admin while the default password is still set."""

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


LONG_JOB_CHECK_INTERVAL = 60

@app.before_request
def check_long_running_jobs():
    """Warns about jobs running longer than 3 hours (at most once per minute)."""

    if request.endpoint in (None, 'static', 'favicon', 'apple_touch_icon', 'history_job_status', 'raw_playbook_graph'):
        return
    if not current_user.is_authenticated:
        return

    now = time.time()
    if now - session.get('long_job_checked_at', 0) < LONG_JOB_CHECK_INTERVAL:
        return
    session['long_job_checked_at'] = now

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT job_id, script_name, pid
        FROM history_jobs
        WHERE status = 'running'
        AND pid IS NOT NULL
        AND started_at < DATE_SUB(NOW(), INTERVAL 3 HOUR)
    """)
    long_running = cur.fetchall()
    cur.close()
    conn.close()

    for job_id, script_name, pid in long_running:
        flash_key = f"long_job_warned_{job_id}"
        if session.get(flash_key):
            continue

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
    """Serves the Apple touch icon."""

    return send_from_directory(app.static_folder, 'apple-touch-icon.png')


# ---------------------
#   Logout route
# ---------------------
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    """Logs out and clears the session."""

    audit("logout")
    logout_user()
    session.clear()
    flash("Logged out", "success")
    return redirect(url_for("login"))