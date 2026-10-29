# Installation with Docker

Instead of `setup.sh`, NetPAC can run in Docker. The image contains NetPAC with Python, Ansible
and all dependencies on its own Ubuntu base, so the host can run any Linux distribution with
Docker (e.g. Ubuntu 24.04).

- Web interface, scheduler and executor run as three containers from the same image, plus nginx
  as reverse proxy.
- All containers use the host network, so `DB_IP=127.0.0.1` works as with a normal installation.
- The database stays on the host.
- You only need two files: `docker-compose.yml` and `secret.env`.

**Requirements on the host:**

- Docker Engine with the Compose plugin, Compose 2.23 or newer
- MariaDB 10.11 or newer (tested with 11.8)
- Free ports 80 and 443

## 1. Prepare the server and the database

Create the user `netpac` and the database exactly as for the normal installation:

- [Prepare the server](install-setup.md#1-prepare-the-server)
- [Create the database](install-setup.md#2-create-the-database)

No schema has to be imported — the migrations are part of the image and create all tables on
the first start.

## 2. Install Docker

```bash
sudo apt install docker.io docker-compose-v2
docker compose version
```

`docker compose version` must show 2.23 or newer.

> [!CAUTION]
> Don't install the package `docker-compose`: it is the old Compose v1 (command `docker-compose`
> with a hyphen), which can't read NetPAC's docker-compose.yml. If the Ubuntu version is too old,
> use Docker's official repository (docs.docker.com, "Install Docker Engine on Ubuntu").

Allow the user `netpac` to use Docker and log in again so the new group takes effect:

```bash
sudo usermod -aG docker netpac
su - netpac
docker ps
```

`docker ps` must work without `sudo`. Members of the `docker` group have root-equivalent rights
on the host, so only add the NetPAC user.

## 3. Download and configure

All following steps as user `netpac`:

```bash
mkdir -p ~/bin/netpac && cd ~/bin/netpac
curl -O https://raw.githubusercontent.com/JimPeterle/NetPAC/main/docker/docker-compose.yml
curl -o secret.env https://raw.githubusercontent.com/JimPeterle/NetPAC/main/config/secret_examples.env
chmod 600 secret.env
vim secret.env
```

Fill in `secret.env` as described in [Configure](install-setup.md#4-configure), including the
`ENCRYPTION_KEY`. Keep a backup of this file.

## 4. Start

```bash
docker compose up -d
docker compose ps
```

After about 30 seconds all four containers should be `Up` and `web` should be `healthy`.
On the first start a self-signed certificate is created in `/etc/netpac/certs`. Then open
`https://<server IP>` and log in with **admin** / **admin**.

If a container keeps restarting, see [Docker containers don't start](troubleshooting.md#docker-containers-dont-start).

## Data and folders

The containers use the same paths as a normal installation. They are stored on the host:

| Host | Content |
|---|---|
| `/var/lib/netpac` | Scripts, playbooks, Git sync, graphs |
| `/var/log/netpac` | Log files |
| `/etc/netpac/certs` | TLS certificate |
| `~/bin/netpac/backups` | Database backups (next to docker-compose.yml) |

The Python venv, Ansible collections, SSH known_hosts and the Git sync settings are kept in
Docker volumes, so they survive updates.

**File owner:** the containers run as the owner of `secret.env` — normally the user `netpac`,
so files on the host belong to `netpac`. To use another user, set `PUID` and `PGID` in
docker-compose.yml (`id -u`, `id -g`). Folders that don't exist yet are created with this owner;
existing folders must be writable by it.

<details>
<summary>Log rotation on the host</summary>

The log files are not rotated inside the containers. Use logrotate on the host, e.g.
`/etc/logrotate.d/netpac`:

```
/var/log/netpac/*.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su netpac netpac
}
```
</details>

## Updates

The image of the latest release is rebuilt every Monday with the current Ubuntu packages
(security updates, bug fixes of Ansible and Python). Fetch it whenever it suits you — your data,
Python packages and Ansible collections are kept, database changes are applied automatically:

```bash
docker compose pull && docker compose up -d
```

The image tags are `latest`, the major version (e.g. `9`) and the exact version (e.g. `9.0.0`).
Set the image in docker-compose.yml to `ghcr.io/jimpeterle/netpac:9` to receive updates only
within one major version.

## Commands

| Command | |
|---|---|
| `docker compose ps` | Status of the containers |
| `docker compose logs -f executor` | Container output (`web`, `scheduler`, `executor`, `nginx`) |
| `docker compose restart` | Restart everything |
| `docker compose restart nginx` | Use a certificate uploaded under **Settings → SSL/TLS** |
| `docker compose exec web python3 app/db_migrations.py` | Database migration state |

> [!NOTE]
> Playbooks with "Run on the NetPAC server (localhost)" run inside the executor container,
> not on the host.

To remove the Docker installation, see [uninstall.md](uninstall.md#docker-installation).
