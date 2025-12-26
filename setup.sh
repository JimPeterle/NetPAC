#!/bin/bash

##############################################
# NetPAC Automatic Setup Script
# Wird im bereits geklonten Git-Repo ausgeführt
# Installiert und konfiguriert:
# - Python venv
# - Gunicorn
# - Nginx
# - Systemd Services
##############################################

set -e  # Bei Fehler abbrechen

# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   NetPAC Auto-Setup Script        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
echo ""

# ===================================
# KONFIGURATION - HIER ANPASSEN!
# ===================================

DOMAIN=""
PATHCERT=""
PATHPRIVATKEY=""

# ===================================
# MAIN
# ===================================

APP_DIR="$(pwd)"  # Aktuelles Verzeichnis (Git-Repo)
APP_USER="$USER"  # Aktueller User
APP_GROUP="$(id -gn)"  # Primäre Gruppe

# ===================================
# Funktionen
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
# 1. Voraussetzungen prüfen
# ===================================

echo -e "${YELLOW}Checking prerequisites...${NC}"

if [ "$EUID" -eq 0 ]; then 
    print_error "Bitte NICHT als root ausführen!"
    print_warning "Starte mit: ./setup.sh"
    exit 1
fi

# Prüfen ob wir im richtigen Verzeichnis sind
if [ ! -f "netpac.py" ]; then
    print_error "netpac.py nicht gefunden!"
    print_warning "Bitte im NetPAC Git-Repo Verzeichnis ausführen"
    exit 1
fi

# Python 3 prüfen
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 nicht gefunden!"
    echo "Installiere mit: sudo apt install python3 python3-venv python3-pip"
    exit 1
fi

print_status "Python 3: $(python3 --version)"
print_status "Working directory: $APP_DIR"

# ===================================
# 2. Git-Repo prüfen (bereits geklont)
# ===================================

echo ""
echo -e "${YELLOW}Checking Git repository...${NC}"

if [ -d ".git" ]; then
    print_status "Git repository gefunden"
    CURRENT_BRANCH=$(git branch --show-current)
    print_status "Branch: $CURRENT_BRANCH"
else
    print_warning "Kein Git repository gefunden (optional)"
fi

# ===================================
# 3. Virtual Environment
# ===================================

echo ""
echo -e "${YELLOW}Setting up Python virtual environment...${NC}"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_status "Virtual environment erstellt"
else
    print_warning "venv existiert bereits"
fi

source venv/bin/activate
print_status "Virtual environment aktiviert"

# ===================================
# 4. Dependencies installieren
# ===================================

echo ""
echo -e "${YELLOW}Installing Python dependencies...${NC}"

if [ -f "requirements.txt" ]; then
    pip3 install --upgrade pip
    pip3 install -r requirements.txt
    print_status "Dependencies installiert"
else
    print_error "requirements.txt nicht gefunden!"
    exit 1
fi

# ===================================
# 6. Gunicorn Config erstellen
# ===================================

echo ""
echo -e "${YELLOW}Creating Gunicorn configuration...${NC}"

cat > gunicorn_config.py << EOF
import os

dir_path = os.path.dirname(os.path.realpath(__file__))

# Gunicorn Configuration
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

print_status "Gunicorn config: gunicorn_config.py"

# ===================================
# 7. Systemd Service erstellen
# ===================================

echo ""
echo -e "${YELLOW}Creating systemd service...${NC}"

sudo tee /etc/systemd/system/netpac.service > /dev/null << EOF
[Unit]
Description=NetPAC with Gunicorn
After=network.target

[Service]
Type=notify
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"

ExecStart=$APP_DIR/venv/bin/gunicorn \\
    -c $APP_DIR/gunicorn_config.py \\
    app:app

Restart=always
RestartSec=10

PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

print_status "Systemd service: /etc/systemd/system/netpac.service"

# ===================================
# 8. Nginx installieren (falls nötig)
# ===================================

echo ""
echo -e "${YELLOW}Checking Nginx installation...${NC}"

if ! command -v nginx &> /dev/null; then
    print_warning "Nginx nicht gefunden"
    read -p "Nginx installieren? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo apt update
        sudo apt install -y nginx
        print_status "Nginx installiert"
    else
        print_error "Nginx wird benötigt!"
        exit 1
    fi
else
    print_status "Nginx: $(nginx -v 2>&1)"
fi

# ===================================
# 9. Nginx Config erstellen
# ===================================

echo ""
echo -e "${YELLOW}Creating Nginx configuration...${NC}"

sudo tee /etc/nginx/sites-available/netpac > /dev/null << EOF
upstream netpac_backend {
    server 127.0.0.1:8443 fail_timeout=0;
}

# HTTP -> HTTPS Redirect
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    # SSL Zertifikate (ANPASSEN!)
    ssl_certificate $PATHCERT;
    ssl_certificate_key $PATHPRIVATKEY;
    
    # SSL Config
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Logging
    access_log /var/log/nginx/netpac_access.log;
    error_log /var/log/nginx/netpac_error.log;

    # Client Settings
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

    # Static Files
    location /static/ {
        alias $APP_DIR/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

print_status "Nginx config: /etc/nginx/sites-available/netpac"

# ===================================
# 10. Nginx Config aktivieren
# ===================================

echo ""
echo -e "${YELLOW}Activating Nginx configuration...${NC}"

# Symlink erstellen
if [ ! -L "/etc/nginx/sites-enabled/netpac" ]; then
    sudo ln -s /etc/nginx/sites-available/netpac /etc/nginx/sites-enabled/
    print_status "Nginx config aktiviert"
fi

# Default Site deaktivieren (optional)
if [ -L "/etc/nginx/sites-enabled/default" ]; then
    read -p "Default Nginx Site deaktivieren? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo rm /etc/nginx/sites-enabled/default
        print_status "Default site deaktiviert"
    fi
fi

# Nginx Config testen
if sudo nginx -t; then
    print_status "Nginx config test erfolgreich"
else
    print_error "Nginx config test fehlgeschlagen!"
    print_warning "Bitte SSL-Zertifikate in /etc/nginx/sites-available/netpac anpassen"
fi

# ===================================
# 11. Services starten
# ===================================

echo ""
echo -e "${YELLOW}Starting services...${NC}"

# Systemd neu laden
sudo systemctl daemon-reload
print_status "Systemd reloaded"

# NetPAC Service
sudo systemctl enable netpac
sudo systemctl start netpac

if sudo systemctl is-active --quiet netpac; then
    print_status "netpac service gestartet"
else
    print_error "netpac service start fehlgeschlagen!"
    echo "Logs: sudo journalctl -u netpac -n 50"
fi

# Nginx
if sudo systemctl is-active --quiet nginx; then
    sudo systemctl reload nginx
    print_status "Nginx reloaded"
else
    sudo systemctl start nginx
    print_status "Nginx gestartet"
fi

# ===================================
# 13. Zusammenfassung
# ===================================

echo ""
echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       Setup abgeschlossen!         ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Konfiguration:${NC}"
echo "  App Directory: $APP_DIR"
echo "  App User: $APP_USER"
echo "  App Port: 8443"
echo "  Domain: $DOMAIN"
echo ""
echo -e "${YELLOW}Services:${NC}"
echo "  Status prüfen: sudo systemctl status netpac nginx"
echo "  netpac neu starten: sudo systemctl restart netpac"
echo "  Nginx neu laden: sudo systemctl reload nginx"
echo ""
echo -e "${YELLOW}Logs:${NC}"
echo "  netpac: sudo journalctl -u netpac -f"
echo "  Gunicorn: tail -f $APP_DIR/logs/gunicorn_error.log"
echo "  Nginx: sudo tail -f /var/log/nginx/${APP_NAME}_error.log"
echo ""
echo -e "${YELLOW}Wichtig:${NC}"
echo "  1. Domain '$DOMAIN' im Script anpassen (Zeile 18)"
echo "  2. SSL-Zertifikate einrichten:"
echo "     sudo apt install certbot python3-certbot-nginx"
echo "     sudo certbot --nginx -d $DOMAIN"
echo "  3. App testen: https://$DOMAIN"
echo ""
echo -e "${GREEN}Viel Erfolg! 🚀${NC}"