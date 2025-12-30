#!/bin/bash

######################################
# NetPAC Automatic Setup Script
# Run inside the already cloned Git repository
#
# Installs and configures:
# - Required directories
# - Python virtual environment
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
# CONFIGURATION – ADJUST HERE!
# ===================================

DOMAIN=""
PATHCERT=""
PATHPRIVATKEY=""

# ===================================
# CHECK USER INPUT
# ===================================

if [ -z "$DOMAIN" ]; then 
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
# MAIN
# ===================================

APP_DIR="$(pwd)"        # Current directory
APP_USER="$USER"        # Current user
APP_GROUP="$(id -gn)"   # Primary group

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
    print_error "Python 3 not found!"
    echo "Install with: sudo apt install python3 python3-venv python3-pip"
    exit 1
fi

print_status "Python detected: $(python3 --version)"
print_status "Working directory: $APP_DIR"

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

sudo chown netpac:netpaclogs /var/log/netpac
sudo chmod 750 /var/log/netpac

if ! id -nG netpac | grep -qw netpaclogs; then
    sudo usermod -aG netpaclogs netpac
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

if ! getent group netpacscript > /dev/null; then
    sudo groupadd netpacscript
fi

sudo chown netpac:netpacscript /var/lib/netpac/scripts
sudo chmod 770 /var/lib/netpac/scripts

if ! id -nG netpac | grep -qw netpacscript; then
    sudo usermod -aG netpacscript netpac
fi

print_status "Finish all for script directory"

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
# 5. PYTHON VIRTUAL ENVIRONMENT
# ===================================

echo ""
echo -e "${YELLOW}Setting up Python virtual environment...${NC}"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_status "Virtual environment created"
else
    print_warning "Virtual environment already exists"
fi

source venv/bin/activate
print_status "Virtual environment activated"

# ===================================
# 6. INSTALL DEPENDENCIES
# ===================================

echo ""
echo -e "${YELLOW}Installing Python dependencies in virtual environment...${NC}"

if [ -f "requirements.txt" ]; then
    pip3 install --upgrade pip
    pip3 install -r requirements.txt
    print_status "Dependencies installed"
else
    print_error "requirements.txt not found!"
    exit 1
fi

# ===================================
# 7. CREATE GUNICORN CONFIG
# ===================================

echo ""
echo -e "${YELLOW}Creating Gunicorn configuration...${NC}"

cat > gunicorn_config.py << EOF
import os

dir_path = os.path.dirname(os.path.realpath(__file__))

# Gunicorn configuration
bind = "127.0.0.1:8443"
workers = 4
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
# 8. CREATE SYSTEMD SERVICE
# ===================================

echo ""
echo -e "${YELLOW}Creating systemd service...${NC}"

sudo tee /etc/systemd/system/netpac.service > /dev/null << EOF
[Unit]
Description=NetPAC Application (Gunicorn)
After=network.target

[Service]
Type=notify
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"

ExecStart=$APP_DIR/venv/bin/gunicorn \\
    -c $APP_DIR/gunicorn_config.py \\
    netpac:app

Restart=always
RestartSec=10

PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

print_status "Systemd service created"

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
# 10. NGINX permission for /home/netpac
# ===================================

echo ""
echo -e "${YELLOW}Checking NGINX permission for /home/netpac...${NC}"

# Hole die aktuellen Berechtigungen (z.B. 750)
PERMS=$(stat -c "%a" /home/netpac)

# Extrahiere das letzte Digit (others)
OTHER_PERMS=${PERMS: -1}

# Prüfe ob others execute hat (1, 3, 5, 7)
if [ $((OTHER_PERMS & 1)) -eq 0 ]; then
    chmod o+x /home/netpac
    print_status "Execute permission granted for others on /home/netpac"
else
    print_status "Execute permission already set on /home/netpac"
fi


# ===================================
# 11. CREATE NGINX CONFIG
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
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name $DOMAIN;

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
# 12. ENABLE NGINX CONFIG
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
# 13. START SERVICES
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
# 14. SUMMARY
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
echo "  Enter the page via: https://$DOMAIN"
echo ""
echo -e "${GREEN}Good luck!${NC}"