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

# ===================================
# CONFIGURATION FROM SECRET.ENV
# ===================================
if [ ! -f "$APP_DIR/secret.env" ]; then
    print_error "secret.env not found!"
    print_warning "Copy secret_examples.env to secret.env and fill in your values"
    exit 1
fi

load_dotenv() {
    export $(grep -v '^#' "$1" | xargs)
}

load_dotenv "$APP_DIR/secret.env"


PATHCERT="${PATHCERT}"
PATHPRIVATEKEY="${PATHPRIVATEKEY}"
DOMAIN="${DOMAIN}"
WORKER="${WORKER}"

# ===================================
# CHECK USER INPUT
# ===================================

if [ -z "$HOSTNAME" ]; then 
    print_error "DOMAIN is not set"
    exit 1
fi

if [ -z "$PATHCERT" ]; then
    print_error "PATHCERT is not set"
    exit 1
fi

if [ -z "$PATHPRIVATKEY" ]; then
    print_error "PATHPRIVATKEY is not set"
    exit 1
fi



# ===================================
# CHECK PREREQUISITES
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
# CREATE LOG DIRECTORY
# ===================================

echo -e "${YELLOW}Checking log directory...${NC}"

if [ ! -d "/var/log/netpac" ]; then
    sudo mkdir -p /var/log/netpac
    print_status "Created log directory"
fi

if ! getent group netpaclogs > /dev/null; then
    sudo groupadd netpaclogs
fi

sudo chown netpac:netpaclogs /var/log/netpac
sudo chmod 750 /var/log/netpac

if ! id -nG netpac | grep -qw netpaclogs; then
    sudo usermod -aG netpaclogs netpac
fi

print_status "Finish all for logs directory"

# ===================================
# CREATE SCRIPT DIRECTORY
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

sudo chown -R netpac:netpacscript /var/lib/netpac/scripts
sudo chmod -R 770 /var/lib/netpac/scripts

if ! id -nG netpac | grep -qw netpacscript; then
    sudo usermod -aG netpacscript netpac
fi

print_status "Finish all for script directory"

# ===================================
# CREATE PLAYBOOK DIRECTORY
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

sudo chown -R netpac:netpacscript /var/lib/netpac/playbooks
sudo chmod -R 770 /var/lib/netpac/playbooks

print_status "Finish all for playbooks directory"

# ===================================
# CREATE GIT DIRECTORY
# ===================================

echo -e "${YELLOW}Checking git directory...${NC}"

if [ ! -d "/var/lib/netpac/git" ]; then
    sudo mkdir -p /var/lib/netpac/git
    sudo chown netpac:netpacscript /var/lib/netpac/git
    sudo chmod 770 /var/lib/netpac/git
    print_status "Created folder for git scripts"
fi

sudo chown -R netpac:netpacscript /var/lib/netpac/git
sudo chmod -R 770 /var/lib/netpac/git

print_status "Finish all for git directory"

# ===================================
# CHECK GIT REPOSITORY
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
# Backup DB
# ===================================

sudo -u netpac tee $APP_DIR/db_secrets.cnf > /dev/null << EOF
[client]
user=${DB_USER}
password=${DB_PW}
host=${DB_IP}
port=${DB_PORT}
EOF

sudo chmod 600 $APP_DIR/db_secrets.cnf
sudo chown netpac:netpac $APP_DIR/db_secrets.cnf

# ===================================
# INSTALL DEPENDENCIES
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
# PYTHON VENV
# ===================================
echo -e "${YELLOW}Creating Python virtual environment...${NC}"

if [ ! -d "$APP_DIR/venv" ]; then
    python3 -m venv "$APP_DIR/venv"
    print_status "Virtual environment created at $APP_DIR/venv"
else
    print_status "Virtual environment already exists"
fi

sudo chown -R netpac:netpac "$APP_DIR/venv"

# ===================================
# CREATE GRAPH FOLDER
# ===================================

if [ ! -d "/var/lib/netpac/graphs" ]; then
    sudo mkdir -p /var/lib/netpac/graphs
    sudo chown netpac:netpacscript /var/lib/netpac/graphs
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
# CREATE GUNICORN CONFIG
# ===================================

echo ""
echo -e "${YELLOW}Creating Gunicorn configuration...${NC}"

cat > gunicorn_config.py << EOF
import os

dir_path = os.path.dirname(os.path.realpath(__file__))

# Gunicorn configuration
bind = "127.0.0.1:8443"
workers = $WORKER
worker_class = "sync"
timeout = 300
keepalive = 5

# Logging
accesslog = "/var/log/netpac/gunicorn_access.log"
errorlog = "/var/log/netpac/gunicorn_error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

# Process
proc_name = "netpac"
pidfile = f"{dir_path}/gunicorn.pid"
EOF

print_status "Gunicorn configuration created"

# ===================================
# CREATE SYSTEMD SERVICE
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
User=netpac
WorkingDirectory=/home/netpac/bin/NetPAC
ExecStart=/usr/bin/python3 /home/netpac/bin/NetPAC/netpac_scheduler.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

print_status "Systemd service created for scheduler"

# ===================================
# INSTALL NGINX (IF REQUIRED)
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
# NGINX permission for /home/netpac
# ===================================

echo ""
echo -e "${YELLOW}Checking NGINX permission for /home/netpac...${NC}"

PERMS=$(stat -c "%a" /home/netpac)

OTHER_PERMS=${PERMS: -1}

if [ $((OTHER_PERMS & 1)) -eq 0 ]; then
    sudo chmod o+x /home/netpac
    print_status "Execute permission granted for others on /home/netpac"
else
    print_status "Execute permission already set on /home/netpac"
fi


# ===================================
# CREATE NGINX CONFIG
# ===================================

echo ""
echo -e "${YELLOW}Creating Nginx configuration...${NC}"

sudo tee /etc/nginx/sites-available/netpac > /dev/null << EOF
upstream netpac_backend {
    server 127.0.0.1:8443 fail_timeout=0;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name $HOSTNAME;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name $HOSTNAME;

    # SSL certificates
    ssl_certificate $PATHCERT;
    ssl_certificate_key $PATHPRIVATKEY;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Logging
    access_log /var/log/nginx/netpac_access.log;
    error_log /var/log/nginx/netpac_error.log;

    # Client settings
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

    # Static files
    location /static/ {
        alias $APP_DIR/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

print_status "Nginx configuration created"

# ===================================
# ENABLE NGINX CONFIG
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
# START SERVICES
# ===================================

echo ""
echo -e "${YELLOW}Starting services...${NC}"

sudo systemctl daemon-reload
print_status "Systemd reloaded"

sudo systemctl enable netpac
sudo systemctl start netpac

if sudo systemctl is-active --quiet netpac; then
    print_status "NetPAC service started"
else
    print_error "NetPAC service failed to start"
    echo "Logs: sudo journalctl -u netpac -n 50"
fi

if sudo systemctl is-active --quiet nginx; then
    sudo systemctl reload nginx
    print_status "Nginx reloaded"
else
    sudo systemctl start nginx
    print_status "Nginx started"
fi

# ===================================
# SECRET.ENV PERMISSIONS
# ===================================

echo ""
echo -e "${YELLOW}Securing secret.env...${NC}"

if [ -f "$APP_DIR/secret.env" ]; then
    chmod 600 "$APP_DIR/secret.env"
    print_status "secret.env permissions set to 600"
else
    print_warning "secret.env not found - create it and run: chmod 600 secret.env"
fi

# ===================================
# SUMMARY
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
echo "  Domain: $HOSTNAME"
echo ""
echo -e "${YELLOW}Services:${NC}"
echo "  Check status: sudo systemctl status netpac nginx"
echo "  Restart NetPAC: sudo systemctl restart netpac"
echo "  Reload Nginx: sudo systemctl reload nginx"
echo ""
echo -e "${YELLOW}Logs:${NC}"
echo "  NetPAC: sudo journalctl -u netpac -f"
echo "  Gunicorn: tail -f /var/log/netpac/gunicorn_error.log"
echo "  Nginx: sudo tail -f /var/log/nginx/netpac_error.log"
echo ""
echo -e "${YELLOW}Final step:${NC}"
echo "  Enter the page via: https://$HOSTNAME"
echo ""
echo -e "${GREEN}Good luck!${NC}"
