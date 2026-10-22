#!/bin/bash

######################################
# NetPAC Automatic update script
# Run inside the already cloned Git repository
######################################

clear

set -e

# ===================================
# COLOR SETTINGS
# ===================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        Updating NetPAC...          ║${NC}"
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

# ===================================
# Update Repository
# ===================================

OLD_COMMIT=$(git rev-parse HEAD)
print_status "Current commit: $OLD_COMMIT"

echo ""

git pull

echo ""

NEW_COMMIT=$(git rev-parse HEAD)

if [ "$OLD_COMMIT" != "$NEW_COMMIT" ]; then
    print_status "Repository updated to commit: $NEW_COMMIT"
else
    print_status "No updates available. You are already on the latest commit: $NEW_COMMIT"
fi 

echo ""

# ===================================
# SYSTEMD SERVICE INFORMATION
# ===================================

read -p "Restart systemd services? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo systemctl restart netpac.service
    sudo systemctl restart netpac-scheduler.service
    print_status "Systemd services restarted successfully."
else
    print_warning "Systemd services not restarted. Please restart them manually if necessary."
fi

# ===================================
# DATABASE UPDATE INFORMATION
# ===================================

echo ""
print_warning "To check if database is up to date, run the following command and update your database if necessary:"
echo "..................................................."
echo "mariadb-dump -u <username> -p --no-data <database_name> | sed 's/ AUTO_INCREMENT=[0-9]*//' | grep -v '^--' > $APP_DIR/schema_production.sql"
echo "diff $APP_DIR/schema_production.sql $APP_DIR/database/schema_pattern.sql"
echo "rm $APP_DIR/schema_production.sql"
echo "..................................................."