# NetPAC - Network Python & Ansible Center

<p align="center">
  <a href="docs/install-setup.md"><img src="https://img.shields.io/badge/platform-Linux%20(Ubuntu%20%7C%20Debian)-E95420?logo=ubuntu&logoColor=white" alt="Platform: Linux (Ubuntu | Debian)"></a>
  <a href="https://github.com/JimPeterle/NetPAC/releases/latest"><img src="https://img.shields.io/github/v/release/JimPeterle/NetPAC?label=release&color=blue" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>
  <br>
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/ansible-playbooks-EE0000?logo=ansible&logoColor=white" alt="Ansible">
  <img src="https://img.shields.io/badge/mariadb-10.11%2B-003545?logo=mariadb&logoColor=white" alt="MariaDB 10.11+">
  <a href="docs/install-docker.md"><img src="https://img.shields.io/badge/docker-supported-2496ED?logo=docker&logoColor=white" alt="Docker supported"></a>
</p>

NetPAC is a web platform for network automation. Keep an inventory of hosts and groups and run
Python scripts and Ansible playbooks against it — with live output, a job queue, schedules,
encrypted credentials and user roles.

> [!NOTE]
> NetPAC is made for **Linux servers (Ubuntu / Debian)**, installed with `setup.sh` or with Docker.
> Windows and macOS are not supported as a host.

<p align="center">
  <img src="docs/screenshots/dashboard.png" alt="NetPAC dashboard with job statistics" width="900">
</p>

## Features

**Automation**
- Run Python scripts and Ansible playbooks against a host, a group or locally
- Live output with Ansible colours, result per host, re-run of failed hosts
- Playbook templates with survey fields, dry run, syntax check and playbook graph
- Schedules with cron expressions
- Job queue: a host is used by one job at a time, timeout after 4 hours, cancel at any time

**Inventory and credentials**
- Hosts and groups with Ansible group variables, search, status filter and bulk edit
- Secrets: username + password, SSH keys and Ansible Vault passwords, stored encrypted
- Scripts and playbooks locally or synced from a Git repository
- Python packages and Ansible collections managed in the web interface

**Security and operation**
- Local users or RADIUS, two-factor authentication (TOTP) for everyone
- Roles: Admin, Operator, Viewer
- Audit log, e-mail and Matrix notifications, health page
- No external resources: everything is served locally, also in networks without internet
- Light and dark mode

<p align="center">
  <img src="docs/screenshots/job-output.png" alt="Live output of a running Ansible playbook in NetPAC" width="900">
</p>

## Quick start

Both ways need a user `netpac` and a MariaDB database first —
see [Prepare the server](docs/install-setup.md#1-prepare-the-server) and
[Create the database](docs/install-setup.md#2-create-the-database).

**With setup.sh** — NetPAC runs directly on the server ([full guide](docs/install-setup.md)):

```bash
mkdir -p ~/bin && cd ~/bin
git clone https://github.com/JimPeterle/NetPAC.git && cd NetPAC
cp config/secret_examples.env config/secret.env && vim config/secret.env
bash maintenance/setup.sh
```

**With Docker** — NetPAC runs in containers ([full guide](docs/install-docker.md)):

```bash
mkdir -p ~/bin/netpac && cd ~/bin/netpac
curl -O https://raw.githubusercontent.com/JimPeterle/NetPAC/main/docker/docker-compose.yml
curl -o secret.env https://raw.githubusercontent.com/JimPeterle/NetPAC/main/config/secret_examples.env
chmod 600 secret.env && vim secret.env
docker compose up -d
```

Then open `https://<server IP>` and log in with **admin** / **admin**. Set up TOTP and change the
password right away under **Settings → User**.

## Documentation

| | |
|---|---|
| [Installation with setup.sh](docs/install-setup.md) | Prepare the server, database, configuration, setup |
| [Installation with Docker](docs/install-docker.md) | Containers, data and folders, updates, commands |
| [Configuration and usage](docs/configuration.md) | Login, RADIUS, users and roles, secrets, scripts, playbooks, schedules, notifications |
| [Operation](docs/operation.md) | `netpac` command, updates, job queue, logs, backups |
| [Troubleshooting](docs/troubleshooting.md) | Lost encryption key, containers or services don't start |
| [Remove NetPAC](docs/uninstall.md) | Uninstall with setup.sh or Docker |
| [Development](docs/development.md) | Repository layout, frontend libraries, Docker image |

Security issues: see [SECURITY.md](SECURITY.md).

## License

NetPAC is released under the MIT License: use, copy, modify and distribute it for any purpose, as
long as the license text is included. See [LICENSE](LICENSE).

The third-party libraries and fonts in `app/static/vendor` keep their own licenses (their license
files are included in each folder).
