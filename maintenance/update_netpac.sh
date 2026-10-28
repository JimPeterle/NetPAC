#!/bin/bash

######################################
# NetPAC Automatic update script
# Usage: netpac update (or: bash maintenance/update_netpac.sh)
######################################

[ "$1" = "--after-pull" ] || clear

set -e

# ===================================
# COLOR SETTINGS
# ===================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$1" != "--after-pull" ]; then
    echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║        Updating NetPAC...          ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
    echo ""
fi

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

APP_DIR="$(cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/.." && pwd)"
cd "$APP_DIR"
RESTART_REQUIRED=false

# ===================================
# Update Repository
# ===================================

if [ "$1" != "--after-pull" ]; then
    OLD_COMMIT=$(git rev-parse HEAD)
    print_status "Current commit: $OLD_COMMIT"

    echo ""

    git pull

    echo ""

    NEW_COMMIT=$(git rev-parse HEAD)

    if [ "$OLD_COMMIT" != "$NEW_COMMIT" ]; then
        print_status "Repository updated to commit: $NEW_COMMIT"
        echo ""
        exec bash "$APP_DIR/maintenance/update_netpac.sh" --after-pull
    else
        print_status "No updates available. You are already on the latest commit: $NEW_COMMIT"
    fi
fi

echo ""

# ===================================
# FOLDER LAYOUT (app/, config/, maintenance/)
# ===================================

for file in secret.env db_secrets.cnf git_config.json; do
    if [ -f "$APP_DIR/$file" ] && [ ! -f "$APP_DIR/config/$file" ]; then
        mv "$APP_DIR/$file" "$APP_DIR/config/$file"
        print_status "Moved $file to config/"
        RESTART_REQUIRED=true
    fi
done

for unit in netpac.service netpac-web.service netpac-scheduler.service netpac-executor.service; do
    unit_file="/etc/systemd/system/$unit"
    [ -f "$unit_file" ] || continue
    tmp_file="$(mktemp)"
    sed -e "s#$APP_DIR/netpac_scheduler\.py#$APP_DIR/app/netpac_scheduler.py#" \
        -e "s#$APP_DIR/netpac_executor\.py#$APP_DIR/app/netpac_executor.py#" \
        -e "/--chdir/! s# netpac:app# --chdir $APP_DIR/app netpac:app#" \
        "$unit_file" > "$tmp_file"
    if ! cmp -s "$unit_file" "$tmp_file"; then
        sudo install -m 644 "$tmp_file" "$unit_file"
        print_status "$unit now starts NetPAC from app/"
        RESTART_REQUIRED=true
    fi
    rm -f "$tmp_file"
done

if [ "$RESTART_REQUIRED" = true ]; then
    sudo systemctl daemon-reload
fi

NGINX_SITE=/etc/nginx/sites-available/netpac

if [ -f "$NGINX_SITE" ] && grep -q "alias $APP_DIR/static/;" "$NGINX_SITE"; then
    sudo sed -i "s#alias $APP_DIR/static/;#alias $APP_DIR/app/static/;#" "$NGINX_SITE"
    if sudo nginx -t > /dev/null 2>&1; then
        sudo systemctl reload nginx
        print_status "Nginx now serves static files from app/static"
    else
        print_error "Nginx configuration test failed — check: sudo nginx -t"
    fi
fi

if [ "$(readlink /usr/local/bin/netpac 2>/dev/null)" != "$APP_DIR/maintenance/netpac" ]; then
    chmod 755 "$APP_DIR/maintenance/netpac"
    sudo ln -sf "$APP_DIR/maintenance/netpac" /usr/local/bin/netpac
    print_status "Command installed: netpac (see: netpac help)"
fi

# ===================================
# WEB SERVICE RENAME (netpac -> netpac-web)
# ===================================

WEB_UNIT=/etc/systemd/system/netpac-web.service
OLD_WEB_UNIT=/etc/systemd/system/netpac.service

if [ ! -f "$WEB_UNIT" ] && [ -f "$OLD_WEB_UNIT" ]; then
    sed -e 's/^Description=.*/Description=NetPAC Web Application/' "$OLD_WEB_UNIT" > /tmp/netpac-web.service.$$
    sudo systemctl disable --now netpac.service
    sudo install -m 644 /tmp/netpac-web.service.$$ "$WEB_UNIT"
    rm -f /tmp/netpac-web.service.$$
    sudo rm "$OLD_WEB_UNIT"
    sudo systemctl daemon-reload
    sudo systemctl enable --now netpac-web.service
    print_status "Web service renamed: netpac.service -> netpac-web.service"
    echo ""
fi

# ===================================
# JOB EXECUTOR SERVICE
# ===================================

EXECUTOR_UNIT=/etc/systemd/system/netpac-executor.service
SCHEDULER_UNIT=/etc/systemd/system/netpac-scheduler.service

if [ ! -f "$EXECUTOR_UNIT" ]; then
    if [ -f "$SCHEDULER_UNIT" ]; then
        sed -e 's/^Description=.*/Description=NetPAC Job Executor/' \
            -e 's/netpac_scheduler\.py/netpac_executor.py/' \
            "$SCHEDULER_UNIT" | sudo tee "$EXECUTOR_UNIT" > /dev/null
        sudo systemctl daemon-reload
        sudo systemctl enable --now netpac-executor.service
        print_status "Job executor service created (netpac-executor.service)"
    else
        print_error "$SCHEDULER_UNIT not found, cannot create the job executor service. Without it no jobs are started."
    fi
    echo ""
fi

# ===================================
# SYSTEMD SERVICE INFORMATION
# ===================================

if [ "$RESTART_REQUIRED" = true ]; then
    print_warning "The folder layout changed — restarting the services now."
    REPLY=y
else
    read -p "Restart systemd services? (y/n) " -n 1 -r
    echo ""
fi

if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo systemctl restart netpac-web.service
    sudo systemctl restart netpac-scheduler.service
    sudo systemctl restart netpac-executor.service
    print_status "Systemd services restarted successfully."
else
    print_warning "Systemd services not restarted. Please restart them manually if necessary: netpac restart"
fi

# ===================================
# DATABASE UPDATE INFORMATION
# ===================================

echo ""
print_status "Database changes are applied automatically when NetPAC starts (a backup is created first)."
echo "Check the database state with: netpac db"
