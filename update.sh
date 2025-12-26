#!/bin/bash

##############################################
# NetPAC Update Script
# Automatisches Update der Anwendung
# Wird im Git-Repo Verzeichnis ausgeführt
##############################################

set -e

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

APP_NAME="netpac"
APP_DIR="$(pwd)"

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

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# ===================================
# Header
# ===================================

echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   NetPAC Update Script            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
echo ""

# ===================================
# 1. Prüfungen
# ===================================

echo -e "${YELLOW}Performing pre-update checks...${NC}"

# Im richtigen Verzeichnis?
if [ ! -f "netpac.py" ]; then
    print_error "netpac.py nicht gefunden!"
    print_warning "Bitte im NetPAC Verzeichnis ausführen"
    exit 1
fi

# Git Repository?
if [ ! -d ".git" ]; then
    print_error "Kein Git repository gefunden!"
    print_warning "Update nur für Git-Installationen möglich"
    exit 1
fi

# Virtual Environment?
if [ ! -d "venv" ]; then
    print_error "Virtual Environment nicht gefunden!"
    print_warning "Bitte zuerst setup.sh ausführen"
    exit 1
fi

print_status "Alle Prüfungen bestanden"

# ===================================
# 2. Aktuelle Version anzeigen
# ===================================

echo ""
echo -e "${YELLOW}Current version:${NC}"
CURRENT_COMMIT=$(git rev-parse --short HEAD)
CURRENT_BRANCH=$(git branch --show-current)
print_info "Branch: $CURRENT_BRANCH"
print_info "Commit: $CURRENT_COMMIT"

# ===================================
# 3. Änderungen prüfen
# ===================================

echo ""
echo -e "${YELLOW}Checking for updates...${NC}"

git fetch origin

UPDATES=$(git log HEAD..origin/$CURRENT_BRANCH --oneline)

if [ -z "$UPDATES" ]; then
    print_status "Keine Updates verfügbar"
    print_info "Du bist bereits auf dem neuesten Stand!"
    exit 0
fi

echo -e "${YELLOW}Available updates:${NC}"
echo "$UPDATES"
echo ""

# ===================================
# 4. Bestätigung
# ===================================

read -p "Update durchführen? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_warning "Update abgebrochen"
    exit 0
fi

# ===================================
# 5. Backup der Config
# ===================================

echo ""
echo -e "${YELLOW}Creating backup...${NC}"

if [ -f "secret.env" ]; then
    cp secret.env secret.env.backup
    print_status "Config gesichert: secret.env.backup"
fi

# Lokale Änderungen?
if ! git diff-index --quiet HEAD --; then
    print_warning "Lokale Änderungen gefunden!"
    read -p "Änderungen stashen? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git stash
        print_status "Änderungen gestasht"
        STASHED=true
    fi
fi

# ===================================
# 6. Git Pull
# ===================================

echo ""
echo -e "${YELLOW}Pulling latest changes...${NC}"

git pull origin $CURRENT_BRANCH

NEW_COMMIT=$(git rev-parse --short HEAD)
print_status "Update erfolgreich!"
print_info "Neue Version: $NEW_COMMIT"

# Stash zurückholen?
if [ "$STASHED" = true ]; then
    echo ""
    read -p "Gestashte Änderungen zurückholen? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if git stash pop; then
            print_status "Änderungen wiederhergestellt"
        else
            print_error "Konflikt beim Wiederherstellen!"
            print_warning "Bitte manuell lösen: git stash pop"
        fi
    fi
fi

# ===================================
# 7. Virtual Environment aktivieren
# ===================================

echo ""
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate
print_status "venv aktiviert"

# ===================================
# 8. Dependencies prüfen/aktualisieren
# ===================================

echo ""
echo -e "${YELLOW}Checking dependencies...${NC}"

if [ -f "requirements.txt" ]; then
    # Prüfen ob neue Dependencies
    pip install --upgrade pip -q
    
    read -p "Dependencies aktualisieren? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        pip install -r requirements.txt --upgrade
        print_status "Dependencies aktualisiert"
    else
        pip install -r requirements.txt
        print_status "Dependencies überprüft"
    fi
else
    print_error "requirements.txt nicht gefunden!"
fi

# ===================================
# 10. Service neu starten
# ===================================

echo ""
echo -e "${YELLOW}Restarting service...${NC}"

# Prüfen ob Service existiert
if systemctl list-unit-files | grep -q "$APP_NAME.service"; then
    sudo systemctl restart $APP_NAME
    sleep 2
    
    # Status prüfen
    if sudo systemctl is-active --quiet $APP_NAME; then
        print_status "Service erfolgreich neu gestartet"
    else
        print_error "Service-Start fehlgeschlagen!"
        echo ""
        echo -e "${RED}Fehler-Logs:${NC}"
        sudo journalctl -u $APP_NAME -n 20 --no-pager
        exit 1
    fi
else
    print_warning "Systemd Service nicht gefunden"
    print_info "Starte Service manuell oder führe setup.sh aus"
fi

# ===================================
# 11. Nginx Config prüfen (optional)
# ===================================

if [ -f "netpac.nginx" ]; then
    echo ""
    read -p "Nginx Config aktualisieren? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo cp netpac.nginx /etc/nginx/sites-available/netpac
        if sudo nginx -t 2>/dev/null; then
            sudo systemctl reload nginx
            print_status "Nginx config aktualisiert"
        else
            print_error "Nginx config test fehlgeschlagen!"
        fi
    fi
fi

# ===================================
# 12. Cleanup
# ===================================

echo ""
echo -e "${YELLOW}Cleaning up...${NC}"

# Alte .pyc Dateien löschen
find . -type f -name "*.pyc" -delete
find . -type d -name "__pycache__" -delete
print_status "Python cache bereinigt"

# ===================================
# 13. Status & Zusammenfassung
# ===================================

echo ""
echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      Update abgeschlossen!         ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Versions-Info:${NC}"
echo "  Vorher: $CURRENT_COMMIT"
echo "  Nachher: $NEW_COMMIT"
echo "  Branch: $CURRENT_BRANCH"
echo ""
echo -e "${YELLOW}Status:${NC}"

if systemctl list-unit-files | grep -q "$APP_NAME.service"; then
    echo "  Service: $(sudo systemctl is-active $APP_NAME)"
    echo ""
    echo -e "${YELLOW}Nützliche Befehle:${NC}"
    echo "  Status: sudo systemctl status $APP_NAME"
    echo "  Logs: sudo journalctl -u $APP_NAME -f"
    echo "  Restart: sudo systemctl restart $APP_NAME"
fi

echo ""
echo -e "${YELLOW}Changelog:${NC}"
git log --oneline --decorate -5

echo ""
echo -e "${GREEN}Update erfolgreich! 🚀${NC}"

# ===================================
# 14. Post-Update Hinweise
# ===================================

# Prüfe ob secret.env.example aktualisiert wurde
if git diff --name-only $CURRENT_COMMIT $NEW_COMMIT | grep -q "secret.env.example"; then
    echo ""
    print_warning "secret.env.example wurde aktualisiert!"
    print_info "Bitte prüfe ob neue Config-Parameter hinzugefügt wurden:"
    echo "  diff secret.env secret.env.example"
fi

# Prüfe ob requirements.txt aktualisiert wurde
if git diff --name-only $CURRENT_COMMIT $NEW_COMMIT | grep -q "requirements.txt"; then
    echo ""
    print_warning "requirements.txt wurde aktualisiert"
    print_info "Neue Dependencies wurden installiert"
fi

# Prüfe ob Nginx Config aktualisiert wurde
if git diff --name-only $CURRENT_COMMIT $NEW_COMMIT | grep -q "netpac.nginx"; then
    echo ""
    print_warning "Nginx Config wurde aktualisiert"
    print_info "Bitte prüfe ob Änderungen übernommen werden sollen"
fi

echo ""
