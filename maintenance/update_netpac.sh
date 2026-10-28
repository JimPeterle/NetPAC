#!/bin/bash

######################################
# NetPAC Automatic update script
# Run inside the already cloned Git repository
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

APP_DIR="$(pwd)"

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
        exec bash "$APP_DIR/update_netpac.sh" --after-pull
    else
        print_status "No updates available. You are already on the latest commit: $NEW_COMMIT"
    fi
fi

echo ""

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

read -p "Restart systemd services? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo systemctl restart netpac-web.service
    sudo systemctl restart netpac-scheduler.service
    sudo systemctl restart netpac-executor.service
    print_status "Systemd services restarted successfully."
else
    print_warning "Systemd services not restarted. Please restart them manually if necessary."
fi

# ===================================
# DATABASE UPDATE INFORMATION
# ===================================

echo ""
print_status "Database changes are applied automatically when NetPAC starts (a backup is created first)."
echo "Check the database state with: python3 $APP_DIR/netpac_migrations.py"