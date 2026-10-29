# Configuration and usage

## Login and two-factor authentication

- Users log in with a local account or via RADIUS.
- Every user sets up two-factor authentication (TOTP) on the first login.
- On the first start, log in with **admin** / **admin**, set up TOTP and change the password right
  away under **Settings → User**. NetPAC shows a warning as long as the default password is in use.
- Local users change their own password under **Settings → User**. RADIUS passwords are managed by
  the RADIUS server.

## RADIUS

An admin configures the RADIUS server under **Settings → RADIUS** and can test it there. The shared
secret is stored encrypted. The RADIUS server must send a valid Message-Authenticator
(protection against BlastRADIUS, CVE-2024-3596), otherwise the login is rejected.

RADIUS users are created on their first login with the role Viewer.

## Users and roles

Every user has one of three roles:

| Role | Permissions |
|---|---|
| **Admin** | Everything, including Settings (users and roles, RADIUS, notifications, Git repository, SSL, backups, logs, audit log) and Health |
| **Operator** | Everything except Settings and Health: run scripts and playbooks, manage hosts, groups, templates, schedules, secrets, Python packages and Ansible collections |
| **Viewer** | View only: hosts, scripts, playbooks, templates, schedules, job history and the list of secrets — no changes |

- An admin assigns roles under **Settings → User**; changes take effect immediately.
- The local user `admin` always has the Admin role and can't be deleted. Further users can be admins as well.
- Actions a role may not use are hidden. If called anyway, NetPAC shows a message and records
  `access.denied` in the audit log.
- All operators see and manage all schedules. A schedule runs in the name of its owner. If the owner
  is deleted or downgraded to Viewer, their schedules are paused; an operator who activates such a
  schedule again becomes its owner.
- When roles are introduced by an update, existing users become Operator and `admin` becomes Admin.

> [!IMPORTANT]
> Give the Operator role only to people you trust with the server itself. Operators run scripts
> and playbooks, set Ansible variables and install Python packages and Ansible collections — all
> of this executes code on the NetPAC server as the NetPAC user, which can read `config/secret.env`.
> The roles protect against mistakes and limit Viewers; they are not a barrier against a malicious
> Operator.

## Hosts and groups

Hosts are created, edited and deleted in the web interface and can belong to several groups.
Groups can carry Ansible variables (one `key=value` per line). The host list can be searched and
filtered by status; several hosts can be edited at once.

## Secrets

Credentials are stored encrypted under **Secrets** and passed to scripts and playbooks at runtime:

| Type | Use |
|---|---|
| Username + password | Environment variables `SECRET_1_USERNAME`, `SECRET_1_PASSWORD`, … |
| SSH key | Temporary key file; passed to Ansible as `--private-key` |
| Ansible Vault password | Passed to Ansible as `--vault-id`, decrypts vault files and `!vault` strings |

The dashboard explains how to use them in Python scripts and playbooks. Put passwords into secrets,
not into extra vars: values of variables like `password`, `secret` or `token` are hidden in the job
history, but secrets are the safe place for credentials.

## Python scripts

- All scripts under `/var/lib/netpac/scripts` are shown in the web interface and can be started
  against a host, a group or without a target.
- Variables can be passed at start; scripts can be scheduled.
- A Python virtual environment (venv) is available for scripts. Packages are installed, updated
  and removed in the web interface.

## Ansible playbooks

- All playbooks under `/var/lib/netpac/playbooks` are shown in the web interface and can be started
  against a host, a group or locally on the NetPAC server.
- Extra vars at start, syntax check, dry run (`--check --diff`) and a visual graph
  (ansible-playbook-grapher).
- **Playbook templates** save a playbook together with target, extra vars, secrets and survey fields
  (text, number, selection, checkbox, password …) for repeatable launches.
- For playbook jobs, the **Hosts** tab shows the result per host; failed hosts can be re-run with one click.
- Ansible collections are installed, updated and removed in the web interface. Collections of the
  system installation are shown separately as read-only.

## Git sync

Scripts and playbooks can be synced from a Git repository. An admin sets repository, branch and
access token under **Settings → Git**; operators start the sync with the **Sync** button. Scripts
and playbooks share the same repository.

## Schedules

Scripts and playbooks can be scheduled with cron expressions (hourly, daily, weekly or custom),
each with target, variables and secrets. A schedule is skipped while its previous run is still
waiting in the queue.

## Notifications

NetPAC sends e-mail or Matrix messages when jobs finish (completed, failed, timeout, cancelled).
An admin configures the mail server and Matrix access under **Settings → Notifications** and defines
rules per recipient, status and job type. Each rule can be tested.

## TLS certificate

The installation creates a self-signed certificate. Upload your own certificate and key under
**Settings → SSL/TLS**, then reload nginx (`sudo systemctl reload nginx`, with Docker
`docker compose restart nginx`).
