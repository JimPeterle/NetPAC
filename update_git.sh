#!/bin/bash

######################################
# NetPAC Update Script
# Updates the application from Git
######################################

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        NetPAC Updater              ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
echo ""

# ===================================
# LOGGING
# ===================================

LOG_FILE="/var/log/netpac/update.log"
TIMESTAMP=$(/usr/bin/date '+%Y-%m-%d %H:%M:%S')

log() {
    echo "[$TIMESTAMP] $1" | sudo tee -a "$LOG_FILE" > /dev/null
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
# ERROR HANDLER
# ===================================

cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        print_error "Update failed with exit code $exit_code"
        
        # Restore from backup if exists
        if [ -f ".update_backup_marker" ]; then
            print_warning "Attempting to restore from backup..."
            restore_backup
        fi
    fi
}

trap cleanup EXIT

# ===================================
# PREREQUISITES
# ===================================

APP_DIR="$(pwd)"
BACKUP_DIR="${APP_DIR}/.update_backup"
PROTECTED_FILES=("secret.env" "gunicorn_config.py" ".env")

# Check if we're in the right directory
if [ ! -f "netpac.py" ]; then
    print_error "netpac.py not found!"
    print_warning "Please run this script inside the NetPAC directory"
    exit 1
fi

# Check if Git repository exists
if [ ! -d ".git" ]; then
    print_error "Not a Git repository!"
    exit 1
fi

# Check if running as correct user (not root)
if [ "$EUID" -eq 0 ]; then
    print_error "Please DO NOT run this script as root!"
    print_warning "Run it as the application user"
    exit 1
fi

# Check if systemd service exists
if systemctl status netpac.service &> /dev/null || systemctl list-unit-files netpac.service &> /dev/null; then
    print_status "netpac.service found"
else
    print_error "netpac.service not found!"
    print_warning "Please run setup.sh first"
    exit 1
fi

log "========================================"
log "Update started by user: $USER"

# ===================================
# BACKUP FUNCTION
# ===================================

create_backup() {
    print_info "Creating backup..."
    
    # Create backup directory
    if [ -d "$BACKUP_DIR" ]; then
        rm -rf "$BACKUP_DIR"
    fi
    mkdir -p "$BACKUP_DIR"
    
    # Backup protected files
    for file in "${PROTECTED_FILES[@]}"; do
        if [ -f "$file" ]; then
            cp "$file" "$BACKUP_DIR/"
            print_status "Backed up: $file"
        fi
    done
    
    # Backup current commit hash
    git rev-parse HEAD > "$BACKUP_DIR/last_commit.txt"
    
    # Create marker file
    touch .update_backup_marker
    
    print_status "Backup created"
}

restore_backup() {
    print_warning "Restoring from backup..."
    
    if [ ! -d "$BACKUP_DIR" ]; then
        print_error "Backup directory not found!"
        return 1
    fi
    
    # Restore protected files
    for file in "${PROTECTED_FILES[@]}"; do
        if [ -f "$BACKUP_DIR/$file" ]; then
            cp "$BACKUP_DIR/$file" "$file"
            print_status "Restored: $file"
        fi
    done
    
    # Restore to previous commit
    if [ -f "$BACKUP_DIR/last_commit.txt" ]; then
        LAST_COMMIT=$(cat "$BACKUP_DIR/last_commit.txt")
        git reset --hard "$LAST_COMMIT"
        print_status "Restored to commit: $LAST_COMMIT"
    fi
    
    # Restart service
    sudo systemctl restart netpac
    
    rm -f .update_backup_marker
    print_status "Backup restored"
}

cleanup_backup() {
    if [ -d "$BACKUP_DIR" ]; then
        rm -rf "$BACKUP_DIR"
    fi
    rm -f .update_backup_marker
    print_status "Backup cleaned up"
}

# ===================================
# PRE-UPDATE CHECKS
# ===================================

print_info "Running pre-update checks..."

# Check if service is running
if ! sudo systemctl is-active --quiet netpac; then
    print_error "NetPAC service is not running!"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Update cancelled"
        exit 0
    fi
fi

# Check Git status
if ! git diff-files --quiet; then
    print_warning "Uncommitted changes detected in tracked files!"
    git status --short
    echo ""
    read -p "Stash changes and continue? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Update cancelled"
        exit 0
    fi
fi

# Check for protected files
echo ""
print_info "Checking protected files..."
for file in "${PROTECTED_FILES[@]}"; do
    if [ -f "$file" ]; then
        print_status "Found: $file (will be protected)"
    fi
done

# Check disk space
AVAILABLE_SPACE=$(df -BM "$APP_DIR" | awk 'NR==2 {print $4}' | sed 's/M//')
if [ "$AVAILABLE_SPACE" -lt 100 ]; then
    print_error "Not enough disk space! Available: ${AVAILABLE_SPACE}MB"
    exit 1
fi
print_status "Disk space: ${AVAILABLE_SPACE}MB available"

# ===================================
# SHOW CURRENT STATUS
# ===================================

echo ""
echo -e "${YELLOW}Current status:${NC}"
CURRENT_BRANCH=$(git branch --show-current)
print_info "Branch: $CURRENT_BRANCH"
CURRENT_COMMIT=$(git rev-parse --short HEAD)
print_info "Commit: $CURRENT_COMMIT"
CURRENT_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "none")
print_info "Tag: $CURRENT_TAG"
echo ""

# ===================================
# FETCH UPDATES
# ===================================

print_info "Fetching latest changes..."
if ! git fetch origin --tags; then
    print_error "Fetch failed!"
    print_warning "Check your network connection and Git credentials"
    exit 1
fi
print_status "Fetch successful"

# ===================================
# CHECK FOR UPDATES
# ===================================

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/$CURRENT_BRANCH)

if [ "$LOCAL" = "$REMOTE" ]; then
    print_status "Already up to date!"
    echo ""
    print_info "Current version: $CURRENT_COMMIT"
    exit 0
fi

echo ""
print_warning "Updates available!"
echo ""

# Show what will be updated
echo -e "${YELLOW}Changes to be applied:${NC}"
git log --oneline --graph --decorate HEAD..origin/$CURRENT_BRANCH | head -20
echo ""

# Show file changes
echo -e "${YELLOW}Files that will be modified:${NC}"
git diff --name-status HEAD..origin/$CURRENT_BRANCH | head -20
echo ""

# Check for breaking changes in commit messages
BREAKING_CHANGES=$(git log --oneline HEAD..origin/$CURRENT_BRANCH | grep -i "BREAKING\|breaking change" || true)
if [ -n "$BREAKING_CHANGES" ]; then
    echo -e "${RED}⚠️  WARNING: Breaking changes detected!${NC}"
    echo "$BREAKING_CHANGES"
    echo ""
fi

# Confirmation
read -p "Continue with update? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_warning "Update cancelled"
    exit 0
fi

# ===================================
# CREATE BACKUP
# ===================================

echo ""
create_backup

# ===================================
# STASH LOCAL CHANGES
# ===================================

STASHED=false
if ! git diff-index --quiet HEAD --; then
    print_warning "Stashing local changes..."
    STASH_NAME="Auto-stash before update $(date +%Y%m%d-%H%M%S)"
    git stash push -m "$STASH_NAME"
    STASHED=true
    print_status "Changes stashed: $STASH_NAME"
fi

# ===================================
# PULL UPDATES
# ===================================

echo ""
print_info "Pulling latest changes..."

if ! git pull origin "$CURRENT_BRANCH"; then
    print_error "Pull failed!"
    restore_backup
    exit 1
fi

NEW_COMMIT=$(git rev-parse --short HEAD)
print_status "Pull successful"
print_info "Updated to: $NEW_COMMIT"

# ===================================
# RESTORE PROTECTED FILES
# ===================================

echo ""
print_info "Restoring protected files..."

for file in "${PROTECTED_FILES[@]}"; do
    if [ -f "$BACKUP_DIR/$file" ]; then
        cp "$BACKUP_DIR/$file" "$file"
        print_status "Restored: $file"
    fi
done

# ===================================
# UPDATE DEPENDENCIES
# ===================================

echo ""
print_info "Checking Python dependencies..."

if [ ! -f "requirements.txt" ]; then
    print_warning "No requirements.txt found, skipping dependency update"
else
    # Check if requirements changed
    REQUIREMENTS_CHANGED=false
    if git diff --name-only HEAD@{1} HEAD | grep -q "requirements.txt"; then
        REQUIREMENTS_CHANGED=true
        print_warning "requirements.txt has changed"
    fi
    
    if [ "$REQUIREMENTS_CHANGED" = true ]; then
        print_info "Updating Python dependencies..."
        
        if [ ! -d "venv" ]; then
            print_error "Virtual environment not found!"
            restore_backup
            exit 1
        fi
        
        source venv/bin/activate
        
        if ! pip install --upgrade pip; then
            print_error "Failed to upgrade pip"
            restore_backup
            exit 1
        fi
        
        if ! pip install -r requirements.txt; then
            print_error "Failed to install dependencies"
            restore_backup
            exit 1
        fi
        
        print_status "Dependencies updated"
    else
        print_status "No dependency changes detected"
    fi
fi

# ===================================
# VALIDATE CONFIGURATION
# ===================================

echo ""
print_info "Validating configuration..."

# Check if secret.env exists and is valid
if [ -f "secret.env" ]; then
    # Check if it has all required variables
    REQUIRED_VARS=("FLASK_KEY" "DB_USER" "DB_PW" "DB_IP" "DB_DATABASE")
    MISSING_VARS=()
    
    for var in "${REQUIRED_VARS[@]}"; do
        if ! grep -q "^${var}=" secret.env; then
            MISSING_VARS+=("$var")
        fi
    done
    
    if [ ${#MISSING_VARS[@]} -gt 0 ]; then
        print_error "Missing required variables in secret.env:"
        for var in "${MISSING_VARS[@]}"; do
            echo "  - $var"
        done
        restore_backup
        exit 1
    fi
    
    print_status "Configuration valid"
else
    print_error "secret.env not found!"
    restore_backup
    exit 1
fi

# ===================================
# RESTART SERVICES
# ===================================

echo ""
print_info "Restarting services..."

# Stop service
if ! sudo systemctl stop netpac; then
    print_error "Failed to stop NetPAC service"
    restore_backup
    exit 1
fi
print_status "Service stopped"

# Wait a moment
sleep 2

# Start service
if ! sudo systemctl start netpac; then
    print_error "Failed to start NetPAC service"
    print_error "Check logs: sudo journalctl -u netpac -n 50"
    restore_backup
    exit 1
fi
print_status "Service started"

# Wait for service to initialize
print_info "Waiting for service to initialize..."
sleep 5

# Check if service is running
if ! sudo systemctl is-active --quiet netpac; then
    print_error "NetPAC service is not running!"
    print_error "Check logs: sudo journalctl -u netpac -n 50"
    restore_backup
    exit 1
fi
print_status "Service is running"

# Reload Nginx
if sudo systemctl is-active --quiet nginx; then
    if sudo systemctl reload nginx; then
        print_status "Nginx reloaded"
    else
        print_warning "Failed to reload Nginx (non-critical)"
    fi
fi

# ===================================
# CLEANUP
# ===================================

echo ""
print_info "Cleaning up..."

cleanup_backup

# ===================================
# SUMMARY
# ===================================

echo ""
echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        Update completed!           ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}Update Summary:${NC}"
echo "  Previous version: $CURRENT_COMMIT"
echo "  Current version:  $NEW_COMMIT"
echo "  Branch:           $CURRENT_BRANCH"
echo ""

if [ "$STASHED" = true ]; then
    print_warning "Local changes were stashed: $STASH_NAME"
    echo "  To view stashed changes: git stash list"
    echo "  To restore changes:      git stash pop"
    echo ""
fi

echo -e "${YELLOW}Service Status:${NC}"
NETPAC_STATUS=$(sudo systemctl is-active netpac)
NGINX_STATUS=$(sudo systemctl is-active nginx)

if [ "$NETPAC_STATUS" = "active" ]; then
    echo -e "  NetPAC: ${GREEN}$NETPAC_STATUS${NC}"
else
    echo -e "  NetPAC: ${RED}$NETPAC_STATUS${NC}"
fi

if [ "$NGINX_STATUS" = "active" ]; then
    echo -e "  Nginx:  ${GREEN}$NGINX_STATUS${NC}"
else
    echo -e "  Nginx:  ${RED}$NGINX_STATUS${NC}"
fi

echo ""
echo -e "${YELLOW}Useful Commands:${NC}"
echo "  View logs:      sudo journalctl -u netpac -f"
echo "  Service status: sudo systemctl status netpac"
echo "  Restart:        sudo systemctl restart netpac"
echo ""

log "Update completed successfully: $CURRENT_COMMIT -> $NEW_COMMIT"
echo -e "${GREEN}Update successful!${NC}"