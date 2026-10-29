#!/bin/sh
set -e

SECRET_FILE="$APP_DIR/config/secret.env"
CNF_FILE="$APP_DIR/config/db_secrets.cnf"
CERT_DIR=/etc/netpac/certs

fail() {
    echo "[netpac] ERROR: $1" >&2
    exit 1
}

ensure_dir() {
    mkdir -p "$1"
    if [ "$(stat -c %u "$1")" = "0" ]; then
        chown "$PUID:$PGID" "$1"
        chmod "${2:-750}" "$1"
    fi
}

ensure_volume_owner() {
    mkdir -p "$1"
    if [ "$(stat -c %u "$1")" != "$PUID" ]; then
        chown -R "$PUID:$PGID" "$1"
    fi
}

write_db_cnf() {
    python3 - "$SECRET_FILE" "$CNF_FILE" << 'PYEOF'
import os
import sys
from dotenv import dotenv_values

cfg = dotenv_values(sys.argv[1])


def esc(value):
    return (value or "").replace("\\", "\\\\").replace('"', '\\"')


fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write("[client]\n")
    f.write(f'user="{esc(cfg.get("DB_USER"))}"\n')
    f.write(f'password="{esc(cfg.get("DB_PW"))}"\n')
    f.write(f'host="{esc(cfg.get("DB_IP") or "127.0.0.1")}"\n')
    f.write(f'port={cfg.get("DB_PORT") or 3306}\n')
PYEOF
}

create_self_signed_cert() {
    [ -f "$CERT_DIR/netpac.crt" ] && [ -f "$CERT_DIR/netpac.key" ] && return 0
    echo "[netpac] No TLS certificate found, creating a self-signed one in $CERT_DIR"
    openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
        -keyout "$CERT_DIR/netpac.key" -out "$CERT_DIR/netpac.crt" \
        -subj "/CN=$(hostname)" > /dev/null 2>&1
    chown "$PUID:$PGID" "$CERT_DIR/netpac.key" "$CERT_DIR/netpac.crt"
    chmod 640 "$CERT_DIR/netpac.key"
    chmod 644 "$CERT_DIR/netpac.crt"
}

case "$1" in
    web)       set -- python3 -m gunicorn -c gunicorn_config.py --chdir app netpac:app; ROLE=web ;;
    scheduler) set -- python3 app/netpac_scheduler.py; ROLE=scheduler ;;
    executor)  set -- python3 app/netpac_executor.py; ROLE=executor ;;
    *)         ROLE=other ;;
esac

[ -f "$SECRET_FILE" ] || fail "secret.env not found. Put secret.env next to docker-compose.yml (template: secret_examples.env)."

SECRET_UID="$(stat -c %u "$SECRET_FILE")"
SECRET_GID="$(stat -c %g "$SECRET_FILE")"
if [ "$SECRET_UID" = "0" ]; then
    SECRET_UID=1000
    SECRET_GID=1000
fi
PUID="${PUID:-$SECRET_UID}"
PGID="${PGID:-$SECRET_GID}"

if [ "$(id -u)" = "0" ]; then
    [ "$(id -g netpac)" = "$PGID" ] || groupmod -o -g "$PGID" netpac
    [ "$(id -u netpac)" = "$PUID" ] || usermod -o -u "$PUID" netpac

    setpriv --reuid="$PUID" --regid="$PGID" --clear-groups test -r "$SECRET_FILE" \
        || fail "secret.env is not readable for UID $PUID. It must belong to the user that runs NetPAC (e.g. chown netpac:netpac secret.env), or set PUID/PGID in docker-compose.yml."

    ensure_dir /var/log/netpac 750
    for dir in /var/lib/netpac /var/lib/netpac/scripts /var/lib/netpac/scripts/local \
               /var/lib/netpac/playbooks /var/lib/netpac/playbooks/local \
               /var/lib/netpac/git /var/lib/netpac/graphs; do
        ensure_dir "$dir" 770
    done
    ensure_dir "$CERT_DIR" 750
    ensure_dir /home/netpac/bin/netpac_backups 750

    for dir in "$APP_DIR/venv" /home/netpac/.ansible /home/netpac/.ssh /home/netpac/state; do
        ensure_volume_owner "$dir"
    done

    write_db_cnf
    chown "$PUID:$PGID" "$CNF_FILE"

    if [ "$ROLE" = "web" ]; then
        create_self_signed_cert
    fi

    export HOME=/home/netpac USER=netpac
    exec setpriv --reuid="$PUID" --regid="$PGID" --init-groups "$@"
fi

exec "$@"
