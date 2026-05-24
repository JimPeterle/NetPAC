#!/bin/bash

######################################
# NetPAC Uninstall Script
# Removes NetPAC and all its components
######################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}╔════════════════════════════════════╗${NC}"
echo -e "${RED}║        NetPAC Uninstaller          ║${NC}"
echo -e "${RED}╚════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}This script will remove NetPAC components.${NC}"
echo -e "${YELLOW}You will be asked before each step.${NC}"
echo ""

# ===================================
# MAIN
# ===================================
APP_DIR="$(pwd)"

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

confirm() {
    read -p "$(echo -e "${YELLOW}[?]${NC} $1 (y/n) ")" -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# ===================================
# 1. STOP SERVICES
# ===================================

echo -e "${YELLOW}Step 1: Stop services${NC}"

if confirm "Stop and disable NetPAC service?"; then
    if systemctl is-active --quiet netpac 2>/dev/null; then
        sudo systemctl stop netpac
        print_status "NetPAC service stopped"
    else
        print_warning "NetPAC service was not running"
    fi

    if systemctl is-enabled --quiet netpac 2>/dev/null; then
        sudo systemctl disable netpac
        print_status "NetPAC service disabled"
    fi
else
    print_warning "Skipped stopping services"
fi

# ===================================
# 2. REMOVE SYSTEMD SERVICE
# ===================================

echo ""
echo -e "${YELLOW}Step 2: Remove systemd service${NC}"

if confirm "Remove systemd service file (/etc/systemd/system/netpac.service)?"; then
    if [ -f "/etc/systemd/system/netpac.service" ]; then
        sudo rm /etc/systemd/system/netpac.service
        print_status "Systemd service removed"
    else
        print_warning "Service file not found"
    fi
else
    print_warning "Skipped removing systemd service"
fi

if confirm "Should the daemon be reloaded?"; then
    sudo systemctl daemon-reload
    print_status "Daemon was reloaded"
else
    print_warning "Skipped daemon reload"
fi

# ===================================
# 3. REMOVE NGINX CONFIG
# ===================================

echo ""
echo -e "${YELLOW}Step 3: Remove Nginx configuration${NC}"

if confirm "Remove Nginx configuration for NetPAC?"; then
    if [ -L "/etc/nginx/sites-enabled/netpac" ]; then
        sudo rm /etc/nginx/sites-enabled/netpac
        print_status "Nginx site disabled"
    fi

    if [ -f "/etc/nginx/sites-available/netpac" ]; then
        sudo rm /etc/nginx/sites-available/netpac
        print_status "Nginx config removed"
    fi

else
    print_warning "Skipped removing Nginx configuration"
fi

if confirm "Reload Nginx?"; then
    if systemctl is-active --quiet nginx; then
        sudo systemctl reload nginx
        print_status "Nginx reloaded"
    fi
else
    print_warning "Nginx reload failed"
fi

# ===================================
# 4. REMOVE SSL CERTIFICATES
# ===================================

echo ""
echo -e "${YELLOW}Step 4: Remove SSL certificates${NC}"

if confirm "Remove SSL certificates ($PATHCERT and $PATHPRIVATEKEY)?"; then
    if [ -f "$PATHCERT" ]; then
        sudo rm "$PATHCERT"
        print_status "Certificate removed: $PATHCERT"
    else
        print_warning "Certificate not found: $PATHCERT"
    fi

    if sudo test -f "$PATHPRIVATKEY"; then
        sudo rm "$PATHPRIVATKEY"
        print_status "Private key removed: $PATHPRIVATKEY"
    else
        print_warning "Private key not found: $PATHPRIVATKEY"
    fi
else
    print_warning "Skipped removing SSL certificates"
fi

# ===================================
# 5. REMOVE LOG DIRECTORY
# ===================================

echo ""
echo -e "${YELLOW}Step 5: Remove log directory${NC}"

if confirm "Remove log directory (/var/log/netpac)?"; then
    if [ -d "/var/log/netpac" ]; then
        sudo rm -rf /var/log/netpac
        print_status "Log directory removed"
    fi

    if getent group netpaclogs > /dev/null; then
        sudo groupdel netpaclogs
        print_status "Group netpaclogs removed"
    fi
fi

# ===================================
# 6. REMOVE SCRIPT DIRECTORY
# ===================================

echo ""
echo -e "${YELLOW}Step 6: Remove script directory${NC}"

if confirm "Remove script directory (/var/lib/netpac/scripts)?"; then
    if [ -d "/var/lib/netpac" ]; then
        sudo rm -rf /var/lib/netpac
        print_status "Script directory removed"
    fi

    if getent group netpacscript > /dev/null; then
        sudo groupdel netpacscript
        print_status "Group netpacscript removed"
    fi
fi

# ===================================
# 7. REMOVE GUNICORN CONFIG
# ===================================

echo ""
echo -e "${YELLOW}Step 7: Remove Gunicorn configuration${NC}"

if confirm "Remove gunicorn_config.py from $APP_DIR?"; then
    if [ -f "$APP_DIR/gunicorn_config.py" ]; then
        rm "$APP_DIR/gunicorn_config.py"
        print_status "Gunicorn config removed"
    else
        print_warning "Gunicorn config not found"
    fi
else
    print_warning "Skipped removing Gunicorn configuration"
fi

# ===================================
# 8. REMOVE PYTHON PACKAGES
# ===================================

echo ""
echo -e "${YELLOW}Step 8: Remove Python packages${NC}"

if confirm "Remove installed Python packages?"; then
    sudo apt remove -y \
        python3-flask \
        python3-flask-login \
        python3-flask-bcrypt \
        python3-flask-limiter \
        python3-flaskext.wtf \
        python3-pyrad \
        python3-dotenv \
        python3-pymysql \
        python3-cryptography \
        python3-markdown \
        python3-gunicorn \
        python3-pyotp \
        python3-qrcode \
        python3-pil \
        python3-apscheduler \
        python3-sqlalchemy 2>/dev/null || true
    print_status "Python packages removed"
else
    print_warning "Skipped removing Python packages"
fi

# ===================================
# SUMMARY
# ===================================

echo ""
echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      Uninstall completed!          ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
echo ""
print_warning "The NetPAC application directory ($APP_DIR) was NOT removed."
print_warning "Remove it manually if needed: rm -rf $APP_DIR"
echo ""
echo -e "${GREEN}Done!${NC}"
