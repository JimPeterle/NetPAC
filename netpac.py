########## Import Libary ##########
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
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
from flask import send_file
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import logging
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import abort
from flask_wtf.csrf import CSRFProtect
import tempfile
import uuid
from werkzeug.middleware.proxy_fix import ProxyFix

# --------------------
#   Get filepath
# --------------------
dir_path = os.path.dirname(os.path.realpath(__file__))


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
#   Flask logs from CLI not in logs file 
# ---------------------------------------
logging.getLogger('werkzeug').propagate = False


# -------------------------------------------------
#   Filter for removce traceback logs from logfile
# -------------------------------------------------
class TracebackInfoFilter(logging.Filter):
    """Clear or restore the exception on log records"""
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

flask_key = os.getenv("FLASK_KEY")
radius_secret = os.getenv("RADIUS_SECRET")
radius_ip = os.getenv("RADIUS_IP")
radius_nas = os.getenv("RADIUS_NAS")
db_user = os.getenv("DB_USER")
db_pw = os.getenv("DB_PW")
db_ip = os.getenv("DB_IP")
db_database = os.getenv("DB_DATABASE")
db_port = int(os.getenv("DB_PORT"))
path_to_scripts = os.getenv("PATH_TO_SCRIPTS")


# --------------------
#   Flask parameter
# --------------------
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = flask_key
app.config['ENV'] = 'production'
app.config['DEBUG'] = False
app.config['TESTING'] = False
csrf = CSRFProtect(app)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,      # X-Forwarded-For
    x_proto=1,    # X-Forwarded-Proto
    x_host=1,     # X-Forwarded-Host
    x_prefix=1    # X-Forwarded-Prefix
)

def get_real_ip():
    """Hole echte IP hinter Reverse Proxy"""
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
        
        # Eingabevalidierung
        if not username or not password:
            flash("Benutzername und Passwort erforderlich", "danger")
            return redirect(url_for("login"))
        
        if auth_mode == "local":
            conn = get_db()
            cur = conn.cursor()
            
            try:
                sql = "SELECT name, password FROM user WHERE name = %s"
                cur.execute(sql, (username,))
                row = cur.fetchone()
                
                if row is None:
                    logger.warning(f"Login attempt for non-existent user: {username}")
                    flash("Ungültige Login-Daten!", "danger")
                    return redirect(url_for("login"))
                
                local_user, local_hash = row
                
                if bcrypt.check_password_hash(local_hash, password):
                    user = User(local_user)
                    login_user(user)
                    logger.info(f"Successful login: {username}")
                    return redirect(url_for("dashboard"))
                
                logger.warning(f"Failed login attempt from IP: {get_real_ip()}")
                flash("Ungültige Login-Daten!", "danger")
                
            except Exception as e:
                logger.error(f"Login error: {e}")
                flash("Login-Fehler aufgetreten", "danger")
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
                    user = User(username)
                    login_user(user)
                    logger.info(f"Successful RADIUS login: {username}")
                    return redirect(url_for("dashboard"))
                
                logger.warning(f"Failed RADIUS login: {username}")
                flash("Ungültige Login-Daten!", "danger")
                
            except Exception as e:
                logger.error(f"RADIUS error: {e}")
                flash("Login-Fehler aufgetreten", "danger")
            
            return redirect(url_for("login"))

        return redirect(url_for("login"))
    
    return render_template("login.html")


# --------------------
#   Dashboard route
# --------------------
@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db()
    cur = conn.cursor() 

    sql_query_hosts = (f"select count(hostname) from hosts")
    cur.execute(sql_query_hosts)
    all_hosts = cur.fetchone()[0]

    sql_query_groups = (f"SELECT COUNT(DISTINCT host_group) FROM hosts")
    cur.execute(sql_query_groups)
    all_groups = cur.fetchone()[0]

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

    sql_query = (f"SELECT DISTINCT host_group FROM hosts WHERE host_group IS NOT NULL AND host_group <> ''")
    sql_query_2 = (f"SELECT DISTINCT host_group_2 FROM hosts WHERE host_group_2 IS NOT NULL AND host_group_2 <> ''")

    cur.execute(sql_query)
    all_groups_1 = cur.fetchall()

    cur.execute(sql_query_2)
    all_groups_2 = cur.fetchall()

    all_groups = all_groups_1 + all_groups_2
    
    return render_template("groups.html", groups=all_groups)


# ------------------------
#   Hosts for Group route
# ------------------------
@app.route("/hosts/<group>")
@login_required
def hosts_by_group(group):

    conn = get_db()
    cur = conn.cursor()

    try:
        sql_query = "SELECT hostname FROM hosts WHERE host_group = %s or host_group_2 = %s"
        cur.execute(sql_query, (group, group))
        all_hosts = cur.fetchall()

    except pymysql.IntegrityError as e:
        logger.error(f"Exception on /hosts [POST]: {type(e).__name__}: {e}")

    except Exception as e:
        logger.error(f"Exception on /hosts [POST]: {type(e).__name__}: {e}")

    return render_template("hosts.html", hosts=all_hosts, group=group)


# --------------------
#   Hosts route
# --------------------
@app.route("/hosts")
@login_required
def hosts():

    conn = get_db()
    cur = conn.cursor() 

    sql_query = (f"SELECT hostname FROM hosts ORDER BY CAST(SUBSTRING_INDEX(hostname, '-', -1) AS UNSIGNED)")
    cur.execute(sql_query)
    all_hosts = cur.fetchall()
    
    return render_template("hosts.html", hosts=all_hosts)


# -----------------------
#   Add host to DB route
# -----------------------
@app.route("/hosts", methods=["POST"])
@login_required
def add_host():
    hostname = request.form.get("Hostname", "").strip()
    group = request.form.get("Group", "").strip()
    group2 = request.form.get("Group2", "").strip()
    
    # Eingabevalidierung
    import re
    hostname_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9.-]{0,62}$'
    group_pattern = r'^[a-zA-Z0-9_-]{1,50}$'
    
    if not hostname or not re.match(hostname_pattern, hostname):
        return redirect(url_for("hosts"))
    
    if group and not re.match(group_pattern, group):
        return redirect(url_for("hosts"))
    
    if group2 and not re.match(group_pattern, group2):
        return redirect(url_for("hosts"))
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # Prüfen ob Hostname bereits existiert
        sql_check = "SELECT COUNT(*) FROM hosts WHERE hostname = %s"
        cur.execute(sql_check, (hostname,))
        if cur.fetchone()[0] > 0:
            return redirect(url_for("hosts"))
        
        # Parametrisierte Abfrage verwenden
        sql_query = "INSERT INTO hosts (hostname, host_group, host_group_2) VALUES (%s, %s, %s)"
        cur.execute(sql_query, (hostname, group if group else None, group2 if group2 else None))
        conn.commit()
        logging.info(f"Host {hostname} with Group: {group} and {group2} successfuly added")
        
    except pymysql.IntegrityError as e:
        logger.error(f"IntegrityError on /hosts [POST]: {e}")
    except Exception as e:
        logger.error(f"Exception on /hosts [POST]: {type(e).__name__}: {e}")
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
        # Erst prüfen ob Host existiert
        sql_check = "SELECT COUNT(*) FROM hosts WHERE hostname = %s"
        cur.execute(sql_check, (hostname,))
        if cur.fetchone()[0] == 0:
            return redirect(url_for("hosts"))
        
        # Parametrisierte Abfrage
        sql_query = "DELETE FROM hosts WHERE hostname = %s"
        cur.execute(sql_query, (hostname,))
        conn.commit()
        logging.info(f"Host {hostname} successfuly deleted")
        
    except Exception as e:
        logger.error(f"Error deleting host {hostname}: {e}")
    finally:
        cur.close()
        conn.close()
    
    return redirect(url_for("hosts"))


# --------------------
#   Scripts route
# --------------------
@app.route("/scripts")
@login_required
def scripts():

    # Get the list of all files and directories
    dir_list = os.listdir(path_to_scripts)

    return render_template("scripts.html", scripts=dir_list)


# -----------------------------
#   View selected script route
# -----------------------------
@app.route("/scripts/<filename>")
@login_required
def view_script(filename):
    # Sicheren Dateinamen verwenden (entfernt ../ etc.)
    safe_filename = secure_filename(filename)
    
    # Vollständigen Pfad erstellen
    path = os.path.join(path_to_scripts, safe_filename)
    
    # Sicherstellen, dass der Pfad im erlaubten Verzeichnis liegt
    if not os.path.abspath(path).startswith(os.path.abspath(path_to_scripts)):
        logger.warning(f"Path traversal attempt detected: {filename}")
        abort(403)
    
    # Prüfen ob Datei existiert
    if not os.path.exists(path):
        abort(404)
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        return render_template("view_script.html", filename=safe_filename, content=content)
    except Exception as e:
        logger.error(f"Error reading script {safe_filename}: {e}")
        abort(500)


# -----------------------------
#    Run selected script route
# -----------------------------
@app.route("/scripts/<filename>", methods=["POST"])
@login_required
def run_script(filename):

    safe_filename = secure_filename(filename)
    
    target = request.form.get("target", "").strip()
    var_1 = request.form.get("variable1", "").strip()
    var_2 = request.form.get("variable2", "").strip()
    var_3 = request.form.get("variable3", "").strip()
    var = request.form.get("varCount", "0")
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # Erst versuchen ob es eine Gruppe ist
        sql_query = "SELECT hostname FROM hosts WHERE host_group = %s OR host_group_2 = %s"
        cur.execute(sql_query, (target, target))
        targets = cur.fetchall()
        
        if not targets:
            # Dann versuchen ob es ein einzelner Hostname ist
            sql_query = "SELECT hostname FROM hosts WHERE hostname = %s"
            cur.execute(sql_query, (target,))
            targets = cur.fetchall()

        # Eindeutigen temporären Dateinamen erstellen (Race Condition vermeiden)

        temp_hostfile = tempfile.gettempdir() + f"/netpac_hosts_{uuid.uuid4().hex}.txt"
        
        with open(temp_hostfile, "w") as f:
            for t in targets:
                f.write(t[0] + "\n")
        
    except Exception as e:
        logger.error(f"Database error in run_script: {e}")
        return redirect(url_for("scripts"))
    finally:
        cur.close()
        conn.close()
    
    # Pfad validieren
    script_path = os.path.join(path_to_scripts, safe_filename)
    if not os.path.abspath(script_path).startswith(os.path.abspath(path_to_scripts)):
        logger.warning(f"Path traversal attempt in run_script: {filename}")
        abort(403)
    
    if not os.path.exists(script_path):
        return redirect(url_for("scripts"))
   
    try:
        
        # Hostfile-Pfad als Umgebungsvariable setzen (sicherer)
        env = os.environ.copy()
        env['NETPAC_HOSTFILE'] = temp_hostfile
        
        # Script ausführen mit validiertem Input
        if var == "0":
            result = subprocess.run(
                ["python3", script_path],
                capture_output=True, text=True, check=True,
                timeout=300,  # 5 Minuten Timeout
                env=env
            )
        elif var == "1":
            result = subprocess.run(
                ["python3", script_path, var_1],
                capture_output=True, text=True, check=True,
                timeout=300,
                env=env
            )
        elif var == "2":
            result = subprocess.run(
                ["python3", script_path, var_1, var_2],
                capture_output=True, text=True, check=True,
                timeout=300,
                env=env
            )
        elif var == "3":
            result = subprocess.run(
                ["python3", script_path, var_1, var_2, var_3],
                capture_output=True, text=True, check=True,
                timeout=300,
                env=env
            )
        else:
            raise ValueError("Ungültige Variablenanzahl")
        
        output_script = result.stdout
        
    except ValueError as e:
        logger.warning(f"Invalid input in run_script: {e}")
        output_script = str(e)
    except subprocess.TimeoutExpired:
        logger.error(f"Script timeout: {safe_filename}")
        output_script = "Fehler: Script-Ausführung dauerte zu lange (Timeout)"
    except subprocess.CalledProcessError as e:
        logger.error(f"Script error: {safe_filename} - {e.stderr}")
        output_script = f"Fehler bei Script-Ausführung:\n{e.stderr}"
    except Exception as e:
        logger.error(f"Unexpected error in run_script: {e}")
        output_script = "Unerwarteter Fehler bei Script-Ausführung"
    finally:
        if os.path.exists(temp_hostfile):
            os.remove(temp_hostfile)
    
    try:
        with open(script_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        logger.error(f"Error reading script content: {e}")
        content = "Fehler beim Laden des Script-Inhalts"

    session["last_output"] = output_script[-10000:] if len(output_script) > 10000 else output_script
    
    return render_template("view_script.html", filename=safe_filename, content=content, output=output_script)


# -----------------------------
#   Export output as PDF route
# -----------------------------
@app.route('/export_pdf/<filename>')
@login_required
def export_pdf(filename):
    safe_filename = secure_filename(filename)
    
    # Eindeutiger temporärer Pfad
    temp_dir = tempfile.gettempdir()
    pdf_filename = f"netpac_{uuid.uuid4().hex}.pdf"
    pdf_path = os.path.join(temp_dir, pdf_filename)
    
    output = session.get("last_output", "No output available.")
    
    try:
        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(pdf_path)
        story = [Paragraph(output.replace("\n", "<br/>"), styles["BodyText"])]
        doc.build(story)
        
        return send_file(pdf_path, as_attachment=True, 
                        download_name=f"{safe_filename.replace('.py', '')}.pdf")
    finally:
        # Aufräumen nach Download
        if os.path.exists(pdf_path):
            try:
                os.remove(pdf_path)
            except:
                pass


# --------------------
#   Settings route
# --------------------
@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


# --------------------
#   Update route
# --------------------
@app.route("/settings", methods=["POST"])
@login_required
def update():
    
    update_script = f"{dir_path}/update.sh"
    
    # Prüfen ob Script existiert
    if not os.path.exists(update_script):
        logger.error(f"Update script not found: {update_script}")
        output = "Error: update.sh not found!"
        return render_template("settings.html", output=output)
    
    try:
        # Shell-Script ausführen
        result = subprocess.run(
            ["bash", update_script],
            capture_output=True,
            text=True,
            check=True,
            timeout=300,  # 5 Minuten Timeout
            cwd=dir_path  # Im App-Verzeichnis ausführen
        )
        logger.info("Update performed successfully")
        output = result.stdout
        
    except subprocess.TimeoutExpired:
        logger.error("Update timeout")
        output = "Error: Update took too long (timeout after 5 minutes)"
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Update failed: {e.stderr}")
        output = f"Update failed:\n\n{e.stdout}\n\nErrors:\n{e.stderr}"
        
    except Exception as e:
        logger.error(f"Update error: {e}")
        output = f"Unexpected error during update: {str(e)}"
    
    return render_template("settings.html", output=output)


# ---------------------
#   Server error route
# ---------------------
@app.errorhandler(Exception)
def handle_error(e):
    error_code = getattr(e, 'code', 500)
    
    # Detaillierte Fehlermeldung nur im Log
    logger.error(f"Error {error_code}: {type(e).__name__}: {str(e)}")
    
    # Generische Fehlermeldung für den Benutzer
    error_messages = {
        400: "Ungültige Anfrage",
        403: "Zugriff verweigert",
        404: "Seite nicht gefunden",
        500: "Interner Serverfehler"
    }
    
    error_message = error_messages.get(error_code, "Ein Fehler ist aufgetreten")
    
    return render_template("error.html", 
                         error_code=error_code, 
                         error_message=error_message), error_code


# ---------------------
#   Logout route
# ---------------------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "danger")
    return redirect(url_for("login"))
