#!/bin/bash

######################################
# NetPAC Dependency Updater
# Updates Python dependencies only
######################################

set -e
set -u
set -o pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   NetPAC Dependency Updater        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
echo ""

APP_DIR="$(pwd)"
LOG_FILE="/var/log/netpac/dependency_update.log"
VENV_DIR="${APP_DIR}/venv"
REQUIREMENTS_FILE="${APP_DIR}/requirements.txt"

# ===================================
# LOGGING
# ===================================

log() {
    echo "[$(/usr/bin/date '+%Y-%m-%d %H:%M:%S')] $1" | /usr/bin/tee -a "$LOG_FILE"
}

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
    log "INFO: $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    log "ERROR: $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    log "WARNING: $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
    log "INFO: $1"
}

# ===================================
# VALIDATION
# ===================================

print_info "Running validation checks..."

# Check if we're in the right directory
if [ ! -f "netpac.py" ]; then
    print_error "netpac.py not found!"
    print_warning "Please run this script inside the NetPAC directory"
    exit 1
fi

# Check if venv exists
if [ ! -d "$VENV_DIR" ]; then
    print_error "Virtual environment not found at: $VENV_DIR"
    print_warning "Please create a virtual environment first"
    exit 1
fi

# Check if requirements.txt exists
if [ ! -f "$REQUIREMENTS_FILE" ]; then
    print_error "requirements.txt not found!"
    exit 1
fi

# Check if Python3 is available in venv
if [ ! -f "$VENV_DIR/bin/python3" ]; then
    print_error "Python3 not found in virtual environment!"
    exit 1
fi

# Check if pip3 is available in venv
if [ ! -f "$VENV_DIR/bin/pip3" ]; then
    print_error "pip3 not found in virtual environment!"
    exit 1
fi

print_status "All validation checks passed"

log "========================================"
log "Dependency update started by user: $USER"

# ===================================
# BACKUP CURRENT PACKAGES
# ===================================

print_info "Creating backup of current packages..."

BACKUP_FILE="${APP_DIR}/.requirements_backup_$(/usr/bin/date +%Y%m%d_%H%M%S).txt"

# Activate venv and freeze current packages
source "$VENV_DIR/bin/activate"

if "$VENV_DIR/bin/pip3" freeze > "$BACKUP_FILE"; then
    print_status "Backup created: $BACKUP_FILE"
else
    print_warning "Could not create backup (non-critical)"
fi

# ===================================
# SHOW CURRENT STATUS
# ===================================

echo ""
echo -e "${YELLOW}Current Python environment:${NC}"
PYTHON_VERSION=$("$VENV_DIR/bin/python3" --version)
print_info "$PYTHON_VERSION"
PIP_VERSION=$("$VENV_DIR/bin/pip3" --version | head -n1)
print_info "pip: $PIP_VERSION"
echo ""

# ===================================
# UPGRADE PIP
# ===================================

print_info "Upgrading pip..."

if "$VENV_DIR/bin/python3" -m pip install --upgrade pip; then
    print_status "pip upgraded successfully"
    NEW_PIP_VERSION=$("$VENV_DIR/bin/pip3" --version | head -n1)
    print_info "New pip: $NEW_PIP_VERSION"
else
    print_error "Failed to upgrade pip"
    exit 1
fi

echo ""

# ===================================
# INSTALL/UPDATE DEPENDENCIES
# ===================================

print_info "Installing/updating dependencies from requirements.txt..."
echo ""

if "$VENV_DIR/bin/pip3" install -r "$REQUIREMENTS_FILE"; then
    print_status "Dependencies installed/updated successfully"
else
    print_error "Failed to install dependencies"
    print_warning "You can restore from backup: $BACKUP_FILE"
    exit 1
fi

echo ""

# ===================================
# VERIFY INSTALLATION
# ===================================

print_info "Verifying installation..."

FAILED_PACKAGES=()

while IFS= read -r line; do
    # Skip comments and empty lines
    [[ "$line" =~ ^#.*$ ]] && continue
    [[ -z "$line" ]] && continue
    
    # Extract package name (before ==, >=, etc.)
    PACKAGE=$(echo "$line" | sed 's/[>=<].*//' | tr -d '[:space:]')
    
    if "$VENV_DIR/bin/python3" -c "import $PACKAGE" 2>/dev/null; then
        print_status "Verified: $PACKAGE"
    else
        print_warning "Could not verify: $PACKAGE (might use different import name)"
        FAILED_PACKAGES+=("$PACKAGE")
    fi
done < "$REQUIREMENTS_FILE"

echo ""

# ===================================
# SHOW UPDATED PACKAGES
# ===================================

print_info "Checking for updated packages..."

if [ -f "$BACKUP_FILE" ]; then
    CURRENT_FREEZE="${APP_DIR}/.requirements_current.txt"
    "$VENV_DIR/bin/pip3" freeze > "$CURRENT_FREEZE"
    
    echo ""
    echo -e "${YELLOW}Package changes:${NC}"
    
    if diff "$BACKUP_FILE" "$CURRENT_FREEZE" > /dev/null 2>&1; then
        print_info "No packages were updated"
    else
        diff "$BACKUP_FILE" "$CURRENT_FREEZE" | grep -E "^[<>]" | head -n 20 || true
    fi
    
    rm -f "$CURRENT_FREEZE"
fi

# ===================================
# CLEANUP OLD BACKUPS
# ===================================

print_info "Cleaning up old backups (keeping last 5)..."

ls -t "$APP_DIR"/.requirements_backup_*.txt 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true

print_status "Cleanup completed"

# ===================================
# RESTART RECOMMENDATION
# ===================================

echo ""
echo -e "${YELLOW}╔════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║      Restart recommended!          ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════╝${NC}"
echo ""

print_warning "Dependencies have been updated"
print_info "Please restart the NetPAC service:"
echo ""
echo "  sudo systemctl restart netpac"
echo ""

# ===================================
# SUMMARY
# ===================================

echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    Update completed!               ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}Summary:${NC}"
echo "  Python:      $PYTHON_VERSION"
echo "  pip:         $NEW_PIP_VERSION"
echo "  Backup:      $BACKUP_FILE"
if [ ${#FAILED_PACKAGES[@]} -gt 0 ]; then
    echo "  Warnings:    ${#FAILED_PACKAGES[@]} package(s) could not be verified"
fi
echo ""

echo -e "${YELLOW}Useful Commands:${NC}"
echo "  View logs:       tail -f /var/log/netpac/dependency_update.log"
echo "  List packages:   $VENV_DIR/bin/pip3 list"
echo "  Restore backup:  $VENV_DIR/bin/pip3 install -r $BACKUP_FILE"
echo "  Restart service: sudo systemctl restart netpac"
echo ""

log "Dependency update completed successfully"
deactivate

echo -e "${GREEN}Dependencies updated successfully!${NC}"