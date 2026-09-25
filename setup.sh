#!/bin/bash

######################################
# NetPAC Automatic Setup Script
# Run inside the already cloned Git repository
#
# Installs and configures:
# - Required directories
# - Gunicorn
# - Nginx
# - Systemd services
######################################

clear

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        NetPAC Auto-Setup           ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
echo ""

# ===================================
# FUNCTIONS
# ===================================

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# ===================================
# MAIN
# ===================================

APP_DIR="$(pwd)"
APP_USER="$USER"
APP_GROUP="$(id -gn)"
CERT_DIR="/etc/netpac/certs"

read -p "Please enter Domain:" DOMAIN
read -p "Please define Worker (2 x CPU-Cores + 1):" WORKER

# ===================================
# CHECK USER INPUT
# ===================================

if [ -z "$DOMAIN" ]; then 
    print_error "DOMAIN is not set"
    exit 1
fi

if [ -z "$WORKER" ]; then
    print_error "WORKER is not set"
    exit 1
fi

# ===================================
# 1. CHECK PREREQUISITES
# ===================================

echo -e "${YELLOW}Checking prerequisites...${NC}"

if [ "$EUID" -eq 0 ]; then
    print_error "Please DO NOT run this script as root!"
    print_warning "Run it as a normal user: ./setup.sh"
    exit 1
fi

if [ ! -f "netpac.py" ]; then
    print_error "netpac.py not found!"
    print_warning "Please run this script inside the NetPAC Git repository"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    print_error "Python 3 not found! It will be installed now"
    sudo apt install python3
    exit 1
fi

print_status "Python detected: $(python3 --version)"
print_status "Working directory: $APP_DIR"

# ===================================
# 1b. LOAD SECRET.ENV
# ===================================

echo -e "${YELLOW}Loading secret.env...${NC}"

if [ ! -f "$APP_DIR/secret.env" ]; then
    print_error "secret.env not found in $APP_DIR"
    print_warning "Create it first (see README) — it must contain at least DB_USER, DB_PW, DB_IP and DB_PORT"
    exit 1
fi

chmod 600 "$APP_DIR/secret.env"
print_status "secret.env permissions set to 600"

read_env_value() {
    grep -E "^$1=" "$APP_DIR/secret.env" | head -n1 | cut -d= -f2- | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//' || true
}

DB_USER="$(read_env_value DB_USER)"
DB_PW="$(read_env_value DB_PW)"
DB_IP="$(read_env_value DB_IP)"
DB_PORT="$(read_env_value DB_PORT)"

MISSING=()
[ -z "$DB_USER" ] && MISSING+=("DB_USER")
[ -z "$DB_PW" ]   && MISSING+=("DB_PW")
[ -z "$DB_IP" ]   && MISSING+=("DB_IP")
[ -z "$DB_PORT" ] && MISSING+=("DB_PORT")

if [ ${#MISSING[@]} -gt 0 ]; then
    print_error "Missing values in secret.env: ${MISSING[*]}"
    exit 1
fi

print_status "Database settings loaded from secret.env (user: $DB_USER, host: $DB_IP:$DB_PORT)"

# ===================================
# 2. CREATE LOG DIRECTORY
# ===================================

echo -e "${YELLOW}Checking log directory...${NC}"

if [ ! -d "/var/log/netpac" ]; then
    sudo mkdir -p /var/log/netpac
    print_status "Created log directory"
fi

if ! getent group netpaclogs > /dev/null; then
    sudo groupadd netpaclogs
fi

sudo chown "$APP_USER":netpaclogs /var/log/netpac
sudo chmod 750 /var/log/netpac

if ! id -nG "$APP_USER" | grep -qw netpaclogs; then
    sudo usermod -aG netpaclogs "$APP_USER"
fi

print_status "Finish all for logs directory"

# ===================================
# 3. CREATE SCRIPT DIRECTORY
# ===================================

echo -e "${YELLOW}Checking script directory...${NC}"

if [ ! -d "/var/lib/netpac/scripts" ]; then
    sudo mkdir -p /var/lib/netpac/scripts
    print_status "Created Script directory"
fi

if [ ! -d "/var/lib/netpac/scripts/local" ]; then
    sudo mkdir -p /var/lib/netpac/scripts/local
    print_status "Created script for local scripts"
fi

if ! getent group netpacscript > /dev/null; then
    sudo groupadd netpacscript
fi

sudo chown -R "$APP_USER":netpacscript /var/lib/netpac/scripts
sudo chmod -R 770 /var/lib/netpac/scripts

if ! id -nG "$APP_USER" | grep -qw netpacscript; then
    sudo usermod -aG netpacscript "$APP_USER"
fi

print_status "Finish all for script directory"

# ===================================
# 3. CREATE PLAYBOOK DIRECTORY
# ===================================

echo -e "${YELLOW}Checking playbook directory...${NC}"

if [ ! -d "/var/lib/netpac/playbooks" ]; then
    sudo mkdir -p /var/lib/netpac/playbooks
    print_status "Created playbooks directory"
fi

if [ ! -d "/var/lib/netpac/playbooks/local" ]; then
    sudo mkdir -p /var/lib/netpac/playbooks/local
    print_status "Created playbooks/local directory"
fi

sudo chown -R "$APP_USER":netpacscript /var/lib/netpac/playbooks
sudo chmod -R 770 /var/lib/netpac/playbooks

print_status "Finish all for playbooks directory"

# ===================================
# 3. CREATE GIT DIRECTORY
# ===================================

echo -e "${YELLOW}Checking git directory...${NC}"

if [ ! -d "/var/lib/netpac/git" ]; then
    sudo mkdir -p /var/lib/netpac/git
    sudo chown "$APP_USER":netpacscript /var/lib/netpac/git
    sudo chmod 770 /var/lib/netpac/git
    print_status "Created folder for git scripts"
fi

sudo chown -R "$APP_USER":netpacscript /var/lib/netpac/git
sudo chmod -R 770 /var/lib/netpac/git

print_status "Finish all for git directory"

# ===================================
# 4. CHECK GIT REPOSITORY
# ===================================

echo ""
echo -e "${YELLOW}Checking Git repository...${NC}"

if [ -d ".git" ]; then
    print_status "Git repository detected"
    CURRENT_BRANCH=$(git branch --show-current)
    print_status "Current branch: $CURRENT_BRANCH"
else
    print_warning "No Git repository found (optional)"
fi

# ===================================
# 6. Backup DB
# ===================================

cnf_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

sudo -u "$APP_USER" tee "$APP_DIR/db_secrets.cnf" > /dev/null << EOF
[client]
user="$(cnf_escape "$DB_USER")"
password="$(cnf_escape "$DB_PW")"
host="$(cnf_escape "$DB_IP")"
port=${DB_PORT}
EOF

sudo chmod 600 $APP_DIR/db_secrets.cnf
sudo chown "$APP_USER":"$APP_GROUP" "$APP_DIR/db_secrets.cnf"

# ===================================
# 6. INSTALL DEPENDENCIES
# ===================================

echo ""
echo -e "${YELLOW}Install the required packages for Python${NC}"

sudo apt update
sudo apt install python3-flask -y
sudo apt install python3-flask-login -y
sudo apt install python3-flask-bcrypt -y
sudo apt install python3-flask-limiter -y
sudo apt install python3-flaskext.wtf -y
sudo apt install python3-pyrad -y
sudo apt install python3-dotenv -y
sudo apt install python3-pymysql -y
sudo apt install python3-cryptography -y
sudo apt install python3-markdown -y
sudo apt install python3-gunicorn -y
sudo apt install python3-pyotp -y
sudo apt install python3-qrcode -y
sudo apt install python3-pil -y
sudo apt install python3-apscheduler -y
sudo apt install python3-sqlalchemy -y
sudo apt install python3-venv -y

echo ""
echo -e "${YELLOW}Install the required packages for Python${NC}"

sudo apt install ansible -y

echo "${YELLOW}Finished installing${NC}"

# ===================================
# CHECK MINIMUM VERSIONS
# ===================================
echo ""
echo -e "${YELLOW}Checking package versions...${NC}"

if ! python3 - << 'EOF'
import sys
from importlib.metadata import version, PackageNotFoundError

def parse(v):
    parts = []
    for p in v.split(".")[:3]:
        digits = "".join(c for c in p if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts + [0] * (3 - len(parts)))

requirements = [
    ("pyrad",        "2.4",  None),
    ("cryptography", "42.0", None),
    ("APScheduler",  "3.0",  "4.0"),
]

errors = []

if sys.version_info < (3, 10):
    errors.append(f"Python {sys.version.split()[0]} found, >= 3.10 required")

for name, minimum, maximum in requirements:
    try:
        installed = version(name)
    except PackageNotFoundError:
        errors.append(f"{name} is not installed")
        continue
    if parse(installed) < parse(minimum):
        errors.append(f"{name} {installed} found, >= {minimum} required")
    elif maximum and parse(installed) >= parse(maximum):
        errors.append(f"{name} {installed} found, < {maximum} required")
    else:
        print(f"  {name} {installed} OK")

for e in errors:
    print(f"  {e}")

sys.exit(1 if errors else 0)
EOF
then
    print_error "Some packages are too old for NetPAC (see above)."
    print_warning "Use a newer distribution release or install newer versions of these packages manually."
    exit 1
fi

print_status "Package versions OK"

# ===================================
# PYTHON VENV
# ===================================
echo -e "${YELLOW}Creating Python virtual environment...${NC}"

if [ ! -d "$APP_DIR/venv" ]; then
    python3 -m venv "$APP_DIR/venv"
    print_status "Virtual environment created at $APP_DIR/venv"
else
    print_status "Virtual environment already exists"
fi

sudo chown -R "$APP_USER":"$APP_GROUP" "$APP_DIR/venv"

# ===================================
# 7. CREATE GRAPH FOLDER
# ===================================

if [ ! -d "/var/lib/netpac/graphs" ]; then
    sudo mkdir -p /var/lib/netpac/graphs
    sudo chown "$APP_USER":netpacscript /var/lib/netpac/graphs
    sudo chmod 770 /var/lib/netpac/graphs
    print_status "Created graphs directory"
fi

# ===================================
# GRAPHVIZ (optional)
# ===================================
GRAPHVIZ_AVAILABLE=false

if command -v dot &> /dev/null; then
    print_status "graphviz already installed"
    GRAPHVIZ_AVAILABLE=true
else
    read -p "Install graphviz with apt(required for Playbook Graph feature)? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo apt install graphviz -y
        print_status "graphviz installed"
        GRAPHVIZ_AVAILABLE=true
    else
        print_warning "graphviz skipped — install later with: sudo apt install graphviz -y"
        print_warning "ansible-playbook-grapher will be skipped too"
    fi
fi

# ===================================
# ANSIBLE PLAYBOOK GRAPHER (optional)
# ===================================
if [ "$GRAPHVIZ_AVAILABLE" = true ]; then
    if command -v ansible-playbook-grapher &> /dev/null; then
        print_status "ansible-playbook-grapher already installed"
    else
        read -p "Install ansible-playbook-grapher with pip inside venv? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            source $APP_DIR/venv/bin/activate
            pip install ansible-playbook-grapher
            print_status "ansible-playbook-grapher installed in venv"
            deactivate
        else
            echo "..................................................."
            print_warning "ansible-playbook-grapher skipped — install later with:"
            print_warning "source $APP_DIR/venv/bin/activate"
            print_warning "pip install ansible-playbook-grapher"
            print_warning "or Web-Interface -> Python -> Environment"
            echo "..................................................."
        fi
    fi
fi

# ===================================
# 7. CREATE GUNICORN CONFIG
# ===================================

echo ""
echo -e "${YELLOW}Creating Gunicorn configuration...${NC}"

cat > gunicorn_config.py << EOF
import os

dir_path = os.path.dirname(os.path.realpath(__file__))

bind = "127.0.0.1:8443"
workers = $WORKER
worker_class = "sync"
timeout = 300
keepalive = 5

accesslog = "/var/log/netpac/gunicorn_access.log"
errorlog = "/var/log/netpac/gunicorn_error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

proc_name = "netpac"
pidfile = f"{dir_path}/gunicorn.pid"
EOF

print_status "Gunicorn configuration created"

# ===================================
# 8. CREATE SYSTEMD SERVICE
# ===================================

echo ""
echo -e "${YELLOW}Creating systemd service...${NC}"

sudo tee /etc/systemd/system/netpac.service > /dev/null << EOF
[Unit]
Description=NetPAC Application (Gunicorn)
After=network.target mariadb.service

[Service]
Type=notify
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_DIR
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$APP_DIR

ExecStart=/usr/bin/python3 -m gunicorn -c $APP_DIR/gunicorn_config.py netpac:app

Restart=always
RestartSec=10

PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

print_status "Systemd service created"

echo ""
echo -e "${YELLOW}Creating systemd service for scheduler...${NC}"

sudo tee /etc/systemd/system/netpac-scheduler.service > /dev/null << EOF
[Unit]
Description=NetPAC Scheduler
After=network.target mariadb.service

[Service]
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/python3 $APP_DIR/netpac_scheduler.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

print_status "Systemd service created for scheduler"

# ===================================
# 9. INSTALL NGINX (IF REQUIRED)
# ===================================

echo ""
echo -e "${YELLOW}Checking Nginx installation...${NC}"

if ! command -v nginx &> /dev/null; then
    print_warning "Nginx not found"
    read -p "Install Nginx now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo apt update
        sudo apt install -y nginx
        print_status "Nginx installed"
    else
        print_error "Nginx is required!"
        exit 1
    fi
else
    print_status "Nginx detected: $(nginx -v 2>&1)"
fi

# ===================================
# 10. NGINX permission for the app directory
# ===================================

echo ""
echo -e "${YELLOW}Checking NGINX permission for $APP_DIR...${NC}"

DIR="$APP_DIR"
while [ "$DIR" != "/" ]; do
    PERMS=$(stat -c "%a" "$DIR")
    OTHER_PERMS=${PERMS: -1}

    if [ $((OTHER_PERMS & 1)) -eq 0 ]; then
        sudo chmod o+x "$DIR"
        print_status "Execute permission granted for others on $DIR"
    fi

    DIR="$(dirname "$DIR")"
done

print_status "Nginx can reach $APP_DIR/static"

# ===================================
# 11. CREATE NGINX CONFIG
# ===================================

if [ ! -d "$CERT_DIR" ]; then
    sudo mkdir -p "$CERT_DIR"
    sudo chown "$APP_USER":"$APP_GROUP" "$CERT_DIR"
    sudo chmod 750 "$CERT_DIR"
fi

if [ ! -f "$CERT_DIR/netpac.crt" ]; then
    echo "Generating self-signed SSL certificate..."
    
    sudo openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
        -keyout "$CERT_DIR/netpac.key" \
        -out "$CERT_DIR/netpac.crt" \
        -subj "/CN=netpac.local" \
        -addext "subjectAltName=DNS:netpac.local,IP:${DOMAIN}"
    
    sudo chown "$APP_USER":"$APP_GROUP" "$CERT_DIR/netpac.key" "$CERT_DIR/netpac.crt"
    sudo chmod 640 "$CERT_DIR/netpac.key"
    sudo chmod 644 "$CERT_DIR/netpac.crt"
    
    print_status "Self-signed certificate generated at $CERT_DIR"
fi

NGINX_USER=$(grep "^user" /etc/nginx/nginx.conf | awk '{print $2}' | tr -d ';')
if [ -n "$NGINX_USER" ]; then
    sudo usermod -aG "$APP_GROUP" "$NGINX_USER"
    print_status "Added $NGINX_USER to $APP_GROUP group for cert access"
fi

# ===================================
# 12. CREATE NGINX CONFIG
# ===================================

echo ""
echo -e "${YELLOW}Creating Nginx configuration...${NC}"

NGINX_VERSION="$(nginx -v 2>&1 | sed -n 's|.*nginx/\([0-9.]*\).*|\1|p')"

if [ -n "$NGINX_VERSION" ] && [ "$(printf '%s\n' "1.25.1" "$NGINX_VERSION" | sort -V | head -n1)" = "1.25.1" ]; then
    NGINX_LISTEN_SSL="listen 443 ssl;
    http2 on;"
else
    NGINX_LISTEN_SSL="listen 443 ssl http2;"
fi

print_status "Nginx ${NGINX_VERSION:-unknown version} detected — using: $(echo "$NGINX_LISTEN_SSL" | tr -s ' \n' ' ')"

sudo tee /etc/nginx/sites-available/netpac > /dev/null << EOF
upstream netpac_backend {
    server 127.0.0.1:8443 fail_timeout=0;
}

server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    ${NGINX_LISTEN_SSL}
    server_name $DOMAIN;

    ssl_certificate /etc/netpac/certs/netpac.crt;
    ssl_certificate_key /etc/netpac/certs/netpac.key ;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'self'; base-uri 'self'; object-src 'none'" always;

    access_log /var/log/nginx/netpac_access.log;
    error_log /var/log/nginx/netpac_error.log;

    client_max_body_size 16M;

    location / {
        proxy_pass http://netpac_backend;

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_read_timeout 300s;
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;

        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /static/ {
        alias $APP_DIR/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

print_status "Nginx configuration created"

# ===================================
# 13. ENABLE NGINX CONFIG
# ===================================

echo ""
echo -e "${YELLOW}Activating Nginx configuration...${NC}"

if [ ! -L "/etc/nginx/sites-enabled/netpac" ]; then
    sudo ln -s /etc/nginx/sites-available/netpac /etc/nginx/sites-enabled/
    print_status "Nginx configuration enabled"
fi

if [ -L "/etc/nginx/sites-enabled/default" ]; then
    read -p "Disable default Nginx site? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo rm /etc/nginx/sites-enabled/default
        print_status "Default site disabled"
    fi
fi

if sudo nginx -t; then
    print_status "Nginx configuration test passed"
else
    print_error "Nginx configuration test failed!"
fi

# ===================================
# 14. START SERVICES
# ===================================

echo ""
echo -e "${YELLOW}Starting services...${NC}"

sudo systemctl daemon-reload
print_status "Systemd reloaded"

for svc in netpac netpac-scheduler; do
    sudo systemctl enable "$svc"
    sudo systemctl restart "$svc"

    if sudo systemctl is-active --quiet "$svc"; then
        print_status "$svc service started"
    else
        print_error "$svc service failed to start"
        echo "Logs: sudo journalctl -u $svc -n 50"
    fi
done

if sudo systemctl is-active --quiet nginx; then
    sudo systemctl reload nginx
    print_status "Nginx reloaded"
else
    sudo systemctl start nginx
    print_status "Nginx started"
fi

# ===================================
# 16. SUMMARY
# ===================================

echo ""
echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        Setup completed!            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo "  App directory: $APP_DIR"
echo "  App user: $APP_USER"
echo "  App local port: 8443"
echo "  App NGINX port: 443"
echo "  Domain: $DOMAIN"
echo ""
echo -e "${YELLOW}Services:${NC}"
echo "  Check status: sudo systemctl status netpac netpac-scheduler nginx"
echo "  Restart NetPAC: sudo systemctl restart netpac netpac-scheduler"
echo "  Reload Nginx: sudo systemctl reload nginx"
echo ""
echo -e "${YELLOW}Logs:${NC}"
echo "  NetPAC: sudo journalctl -u netpac -f"
echo "  Gunicorn: tail -f /var/log/netpac/gunicorn_error.log"
echo "  Nginx: sudo tail -f /var/log/nginx/netpac_error.log"
echo ""
echo -e "${YELLOW}Final step:${NC}"
echo "  Enter the page via: https://$DOMAIN"
echo ""
echo -e "${GREEN}Good luck!${NC}"
