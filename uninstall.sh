#!/bin/bash

######################################
# NetPAC Uninstall Script
# Removes NetPAC and all its components
# Run inside the NetPAC application directory
######################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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

confirm_destructive() {
    read -p "$(echo -e "${RED}[?]${NC} $1 Type 'yes' to confirm: ")" -r
    [[ $REPLY == "yes" ]]
}

# ===================================
# MAIN
# ===================================

echo -e "${RED}╔════════════════════════════════════╗${NC}"
echo -e "${RED}║        NetPAC Uninstaller          ║${NC}"
echo -e "${RED}╚════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}This script will remove NetPAC components.${NC}"
echo -e "${YELLOW}You will be asked before each step.${NC}"
echo ""

APP_DIR="$(pwd)"

SERVICES=("netpac" "netpac-scheduler")
CERT_BASE_DIR="/etc/netpac"
LOG_DIR="/var/log/netpac"
LIB_DIR="/var/lib/netpac"
BACKUP_DIR="$(dirname "$APP_DIR")/netpac_backups"
DB_NAME="netpac_db"

DB_USER=""
if [ -f "$APP_DIR/secret.env" ]; then
    DB_USER="$(grep -E '^DB_USER=' "$APP_DIR/secret.env" | head -n1 | cut -d= -f2- | tr -d '"'"'"'')"
fi

# ===================================
# 1. STOP SERVICES
# ===================================

echo -e "${YELLOW}Step 1: Stop services${NC}"

if confirm "Stop and disable the NetPAC services (netpac, netpac-scheduler)?"; then
    for svc in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            sudo systemctl stop "$svc"
            print_status "$svc stopped"
        else
            print_warning "$svc was not running"
        fi

        if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            sudo systemctl disable "$svc"
            print_status "$svc disabled"
        fi
    done
else
    print_warning "Skipped stopping services"
fi

# ===================================
# 2. REMOVE SYSTEMD SERVICES
# ===================================

echo ""
echo -e "${YELLOW}Step 2: Remove systemd services${NC}"

if confirm "Remove systemd service files (netpac.service, netpac-scheduler.service)?"; then
    for svc in "${SERVICES[@]}"; do
        if [ -f "/etc/systemd/system/$svc.service" ]; then
            sudo rm "/etc/systemd/system/$svc.service"
            print_status "$svc.service removed"
        else
            print_warning "$svc.service not found"
        fi
    done

    sudo systemctl daemon-reload
    print_status "systemd daemon reloaded"
else
    print_warning "Skipped removing systemd services"
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

    if systemctl is-active --quiet nginx; then
        if sudo nginx -t 2>/dev/null; then
            sudo systemctl reload nginx
            print_status "Nginx reloaded"
        else
            print_error "Nginx configuration test failed — Nginx was NOT reloaded. Check: sudo nginx -t"
        fi
    fi
else
    print_warning "Skipped removing Nginx configuration"
fi

# ===================================
# 4. REMOVE SSL CERTIFICATES
# ===================================

echo ""
echo -e "${YELLOW}Step 4: Remove SSL certificates${NC}"

if confirm "Remove SSL certificate, private key and backups ($CERT_BASE_DIR)?"; then
    if sudo test -d "$CERT_BASE_DIR"; then
        sudo rm -rf "$CERT_BASE_DIR"
        print_status "Removed $CERT_BASE_DIR (certificate, private key, .bak copies)"
    else
        print_warning "$CERT_BASE_DIR not found"
    fi
else
    print_warning "Skipped removing SSL certificates"
fi

# ===================================
# 5. REMOVE LOGS
# ===================================

echo ""
echo -e "${YELLOW}Step 5: Remove logs${NC}"

if confirm "Remove log directory ($LOG_DIR) and NetPAC Nginx logs?"; then
    if [ -d "$LOG_DIR" ]; then
        sudo rm -rf "$LOG_DIR"
        print_status "Log directory removed"
    fi

    sudo rm -f /var/log/nginx/netpac_access.log* /var/log/nginx/netpac_error.log*
    print_status "NetPAC Nginx logs removed"

    if getent group netpaclogs > /dev/null; then
        sudo groupdel netpaclogs
        print_status "Group netpaclogs removed"
    fi
else
    print_warning "Skipped removing logs"
fi

# ===================================
# 6. REMOVE PLAYBOOK/GIT/SCRIPT DIRECTORY
# ===================================

echo ""
echo -e "${YELLOW}Step 6: Remove playbook/git/script directory${NC}"

if confirm "Remove scripts, playbooks, git checkout and graphs ($LIB_DIR)?"; then
    if [ -d "$LIB_DIR" ]; then
        sudo rm -rf "$LIB_DIR"
        print_status "All NetPAC data directories removed"
    fi

    if getent group netpacscript > /dev/null; then
        sudo groupdel netpacscript
        print_status "Group netpacscript removed"
    fi

    sudo rm -f /tmp/netpac_hosts_*.txt /tmp/netpac_inventory_*.ini
else
    print_warning "Skipped removing data directories"
fi

# ===================================
# 7. REMOVE BACKUPS
# ===================================

echo ""
echo -e "${YELLOW}Step 7: Remove database backups${NC}"

if sudo test -d "$BACKUP_DIR"; then
    print_warning "The backups contain password hashes, TOTP secrets and encrypted credentials."
    print_warning "Keep a copy if you might want to restore NetPAC later."
    if confirm_destructive "Permanently delete all backups in $BACKUP_DIR?"; then
        sudo rm -rf "$BACKUP_DIR"
        print_status "Backups removed"
    else
        print_warning "Skipped removing backups"
    fi
else
    print_warning "No backup directory found ($BACKUP_DIR)"
fi

# ===================================
# 8. REMOVE DATABASE
# ===================================

echo ""
echo -e "${YELLOW}Step 8: Remove database${NC}"

print_warning "This deletes the database '$DB_NAME' with ALL NetPAC data (hosts, history, secrets, users)."
if confirm_destructive "Drop database '$DB_NAME'${DB_USER:+ and database user '$DB_USER'@'localhost'}?"; then
    SQL="DROP DATABASE IF EXISTS \`$DB_NAME\`;"
    if [ -n "$DB_USER" ]; then
        SQL="$SQL DROP USER IF EXISTS '$DB_USER'@'localhost';"
    else
        print_warning "DB_USER not found in secret.env — the database user must be removed manually"
    fi

    echo "Enter the MariaDB/MySQL root password (just press Enter if root uses socket authentication):"
    if sudo mysql -u root -p -e "$SQL"; then
        print_status "Database removed${DB_USER:+ (including user '$DB_USER')}"
    else
        print_error "Removing the database failed — remove it manually: sudo mysql -u root -p"
    fi
else
    print_warning "Skipped removing database"
fi

# ===================================
# 9. REMOVE GENERATED FILES IN APP DIRECTORY
# ===================================

echo ""
echo -e "${YELLOW}Step 9: Remove generated files and credentials in $APP_DIR${NC}"

if confirm "Remove gunicorn_config.py, gunicorn.pid, db_secrets.cnf and git_config.json?"; then
    for f in gunicorn_config.py gunicorn.pid db_secrets.cnf git_config.json; do
        if sudo test -f "$APP_DIR/$f"; then
            sudo rm "$APP_DIR/$f"
            print_status "$f removed"
        fi
    done
else
    print_warning "Skipped removing generated files"
fi

# ===================================
# 10. REMOVE PACKAGES
# ===================================

echo ""
echo -e "${YELLOW}Step 10: Remove packages${NC}"

PACKAGES=(
    python3-flask
    python3-flask-login
    python3-flask-bcrypt
    python3-flask-limiter
    python3-flaskext.wtf
    python3-pyrad
    python3-dotenv
    python3-pymysql
    python3-cryptography
    python3-markdown
    python3-gunicorn
    python3-pyotp
    python3-qrcode
    python3-pil
    python3-apscheduler
    python3-sqlalchemy
    python3-venv
    ansible
)

if confirm "Remove the packages installed by setup.sh (only those no other software needs)?"; then
    INSTALLED=()
    for pkg in "${PACKAGES[@]}"; do
        if dpkg -s "$pkg" &> /dev/null; then
            INSTALLED+=("$pkg")
        fi
    done

    if [ ${#INSTALLED[@]} -eq 0 ]; then
        print_warning "None of the packages are installed"
    else
        sudo apt-mark auto "${INSTALLED[@]}" > /dev/null

        echo ""
        echo "The following packages would be removed:"
        TO_REMOVE="$(sudo apt-get --simulate autoremove | awk '/^Remv/ {print "  " $2}')"
        if [ -z "$TO_REMOVE" ]; then
            echo "  (none — all packages are still needed by other software)"
        else
            echo "$TO_REMOVE"
            echo ""
            print_warning "This list can also contain unrelated packages that are no longer needed."
            if confirm "Remove these packages?"; then
                sudo apt-get autoremove -y
                print_status "Packages removed"
            else
                print_warning "Skipped — the packages stay installed (now marked as automatically installed)"
            fi
        fi
    fi
else
    print_warning "Skipped removing packages"
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
print_warning "It may still contain secret.env with your encryption key and database password."
print_warning "Remove it manually if needed: rm -rf $APP_DIR"
echo ""
echo -e "${GREEN}Done!${NC}"
