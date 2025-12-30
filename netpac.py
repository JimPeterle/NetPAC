# --------------------
#   Import Libary 
# --------------------
from flask import Flask, render_template, request, redirect, url_for, flash, session
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
import re
import threading
from datetime import datetime
import json


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
                sql = "SELECT name, password FROM user WHERE name = %s"
                cur.execute(sql, (username,))
                row = cur.fetchone()
                
                if row is None:
                    logger.warning(f"Login attempt for non-existent user: {username}")
                    flash("Invalid login details!", "danger")
                    return redirect(url_for("login"))
                
                local_user, local_hash = row
                
                if bcrypt.check_password_hash(local_hash, password):
                    user = User(local_user)
                    login_user(user)
                    logger.info(f"Successful login: {get_real_ip()}")
                    return redirect(url_for("dashboard"))
                
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
                    user = User(username)
                    login_user(user)
                    logger.info(f"Successful login from IP: {get_real_ip()}")
                    return redirect(url_for("dashboard"))
                
                logger.warning(f"Failed login attempt from IP: {get_real_ip()}")
                flash("Ungültige Login-Daten!", "danger")
                
            except Exception as e:
                logger.error(f"RADIUS error: {e}")
                flash("Login error occurred!", "danger")
            
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

    sql_query = """
        SELECT host_group as group_name FROM hosts 
        WHERE host_group IS NOT NULL AND host_group <> ''
        UNION
        SELECT host_group_2 as group_name FROM hosts 
        WHERE host_group_2 IS NOT NULL AND host_group_2 <> ''
        ORDER BY group_name
    """

    cur.execute(sql_query)
    all_groups = cur.fetchall()
    
    cur.close()
    conn.close()
    
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
    
    conn = get_db()
    cur = conn.cursor()
    
    try:

        sql_check = "SELECT COUNT(*) FROM hosts WHERE hostname = %s"
        cur.execute(sql_check, (hostname,))
        if cur.fetchone()[0] > 0:
            return redirect(url_for("hosts"))
        

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

        sql_check = "SELECT COUNT(*) FROM hosts WHERE hostname = %s"
        cur.execute(sql_check, (hostname,))
        if cur.fetchone()[0] == 0:
            return redirect(url_for("hosts"))
        

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


    dir_list = os.listdir("/var/lib/netpac/scripts")

    return render_template("scripts.html", scripts=dir_list)


# -----------------------------
#   View selected script route
# -----------------------------
@app.route("/scripts/<filename>")
@login_required
def view_script(filename):

    safe_filename = secure_filename(filename)
    

    path = os.path.join("/var/lib/netpac/scripts", safe_filename)
    

    if not os.path.abspath(path).startswith(os.path.abspath("/var/lib/netpac/scripts")):
        logger.warning(f"Path traversal attempt detected: {filename}")
        abort(403)
    

    if not os.path.exists(path):
        abort(404)
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        return render_template("view_script.html", filename=safe_filename, content=content)
    except Exception as e:
        logger.error(f"Error reading script {safe_filename}: {e}")
        abort(500)

# --------------------
#   Run script route
# --------------------
@app.route("/scripts/<filename>", methods=["POST"])
@login_required
def run_script(filename):
    safe_filename = secure_filename(filename)
    
    target = request.form.get("target", "").strip()
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
    
    conn = get_db()
    cur = conn.cursor()
    

    try:
        cur.execute("""
            INSERT INTO script_jobs 
            (script_name, user_id, target, variables, status, started_at) 
            VALUES (%s, %s, %s, %s, 'running', NOW())
        """, (safe_filename, current_user.id, target, json.dumps(variables)))
        
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
        args=(job_id, safe_filename, target, var_1, var_2, var_3, var)
    )
    thread.daemon = True
    thread.start()
    

    flash(f"Script '{safe_filename}' started (Job #{job_id})", "success")
    return redirect(url_for("history"))


# --------------------
#   Background execution
# --------------------
def execute_script_background(job_id, filename, target, var_1, var_2, var_3, var_count):
    
    start_time = datetime.now()
    output_script = ""
    status = "completed"
    
    conn = get_db()
    cur = conn.cursor()
    
    try:

        if target:
            sql_query = "SELECT hostname FROM hosts WHERE host_group = %s OR host_group_2 = %s"
            cur.execute(sql_query, (target, target))
            targets = cur.fetchall()
            
            if not targets:
                sql_query = "SELECT hostname FROM hosts WHERE hostname = %s"
                cur.execute(sql_query, (target,))
                targets = cur.fetchall()
        else:
            targets = []
        

        temp_hostfile = tempfile.gettempdir() + f"/netpac_hosts_{uuid.uuid4().hex}.txt"
        
        with open(temp_hostfile, "w") as f:
            for t in targets:
                f.write(t[0] + "\n")
        
        script_path = os.path.join("/var/lib/netpac/scripts", filename)
        if not os.path.abspath(script_path).startswith(os.path.abspath("/var/lib/netpac/scripts")):
            raise ValueError("Invalid script path")
        
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Script not found: {filename}")
        
        env = os.environ.copy()
        env['NETPAC_HOSTFILE'] = temp_hostfile
        
        if var_count == "0":
            result = subprocess.run(
                ["python3", script_path],
                capture_output=True, text=True, check=True,
                timeout=300, env=env
            )
        elif var_count == "1":
            result = subprocess.run(
                ["python3", script_path, var_1],
                capture_output=True, text=True, check=True,
                timeout=300, env=env
            )
        elif var_count == "2":
            result = subprocess.run(
                ["python3", script_path, var_1, var_2],
                capture_output=True, text=True, check=True,
                timeout=300, env=env
            )
        elif var_count == "3":
            result = subprocess.run(
                ["python3", script_path, var_1, var_2, var_3],
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
        logger.error(f"Script error: {filename} - {e.stderr}")
        
    except Exception as e:
        status = "failed"
        output_script = f"ERROR: {str(e)}"
        logger.error(f"Unexpected error in background script: {e}")
        
    finally:

        if os.path.exists(temp_hostfile):
            os.remove(temp_hostfile)
        

        end_time = datetime.now()
        duration = int((end_time - start_time).total_seconds())
        
        try:
            cur.execute("""
                UPDATE script_jobs 
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
        FROM script_jobs 
        WHERE user_id = %s 
        ORDER BY started_at DESC
        LIMIT 100
    """, (current_user.id,))
    
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
               output, started_at, finished_at, duration
        FROM script_jobs 
        WHERE job_id = %s AND user_id = %s
    """, (job_id, current_user.id))
    
    row = cur.fetchone()
    
    cur.close()
    conn.close()
    
    if not row:
        abort(404)
    
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
        'duration': row[9]
    }
    
    return render_template("history_detail.html", job=job)


# --------------------
#   Export history output as PDF
# --------------------
@app.route('/export_history_pdf/<int:job_id>')
@login_required
def export_history_pdf(job_id):
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT script_name, output, status
        FROM script_jobs 
        WHERE job_id = %s AND user_id = %s
    """, (job_id, current_user.id))
    
    row = cur.fetchone()
    
    cur.close()
    conn.close()
    
    if not row:
        abort(404)
    
    script_name, output, status = row
    
    if not output:
        output = "No output available."
    
    temp_dir = tempfile.gettempdir()
    pdf_filename = f"netpac_history_{job_id}_{uuid.uuid4().hex}.pdf"
    pdf_path = os.path.join(temp_dir, pdf_filename)
    
    try:
        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(pdf_path)
        story = [
            Paragraph(f"<b>History #{job_id} - {script_name}</b><br/><br/>", styles["Heading1"]),
            Paragraph(output.replace("\n", "<br/>"), styles["BodyText"])
        ]
        doc.build(story)
        
        return send_file(pdf_path, as_attachment=True, 
                        download_name=f"history_{job_id}_{script_name.replace('.py', '')}.pdf")
    finally:
        if os.path.exists(pdf_path):
            try:
                os.remove(pdf_path)
            except:
                pass


# ---------------------
#   Settings route
# ---------------------
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    output = None
    
    if request.method == "POST":
        update_script = f"{dir_path}/update_venv.sh"
        
        if not os.path.exists(update_script):
            logger.error(f"Update script not found: {update_script}")
            output = "Error: update.sh not found!"
        else:
            try:
                result = subprocess.run(
                    ["/usr/bin/bash", update_script],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=300,
                    cwd=dir_path
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
    
    return render_template("settings.html", output=output, logs=log_files)


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
#   Server error route
# ---------------------
@app.errorhandler(404)
def not_found_error(error):
    logger.error(f"404 Error - URL: {request.url} - Method: {request.method} - IP: {get_real_ip()}")
    logger.error(f"Referrer: {request.referrer}")
    logger.error(f"User-Agent: {request.headers.get('User-Agent')}")
    
    return render_template("error.html", 
                         error_code=404, 
                         error_message="Seite nicht gefunden"), 404

@app.errorhandler(Exception)
def handle_error(e):
    error_code = getattr(e, 'code', 500)
    
    # WICHTIG: Logge die komplette Exception mit Traceback
    logger.error(f"Error {error_code}: {type(e).__name__}: {str(e)}")
    logger.error(f"URL: {request.url}")
    logger.error(f"Method: {request.method}")
    logger.error(f"Traceback:", exc_info=True)  # Zeigt den vollständigen Traceback
    
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

    session.pop('_flashes', None)
    
    logout_user()
    flash("Logged out", "danger")
    return redirect(url_for("login"))
