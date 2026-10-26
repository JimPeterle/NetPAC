# NetPAC - Network Python & Ansible Center

NetPAC is a network automation and management platform. You can create an inventory of 
hosts and groups and use this inventory for Python scripts and Ansible 
Playbooks.

<p align="center">
  <img src="docs/screenshots/dashboard.png" alt="NetPAC dashboard with job statistics" width="900">
</p>

For login, you can use RADIUS or a local user. All users are required to 
set up two-factor authentication (TOTP) on first login.

For local login you can use for first startup the user **admin** with password **admin**, after login and totp verification please change the default password under Settings -> Change Password of local user. 
If you logged in with the local admin user, you can add more local user. 

For RADIUS login, the local admin configures the RADIUS server under 
Settings -> Radius. The shared secret is stored encrypted in the database.

setup.sh creates a self-signed SSL certificate. Your own certificate 
can be uploaded later under Settings -> SSL/TLS.

## Python

All scripts located under **/var/lib/netpac/scripts** are displayed in the 
GUI and can be executed there. Scripts can also be synced directly from 
a Git repository via the built-in Git Sync feature in the UI.


Python support:
- Running a playbook against a target host, host group, or locally 
  (no target required)
- Passing extra vars at runtime
- Schedule script jobs

A Python virtual environment (venv) is available for scripts and can be 
managed directly in the GUI (install, update, remove packages).

## Ansible Playbooks

All playbooks located under **/var/lib/netpac/playbooks** are displayed 
in the GUI and can be executed there. Playbooks can also be synced 
directly from a Git repository — Scripts and Playbooks share the same 
Git sync target, so both are updated with a single sync.

Playbooks support:
- Running a playbook against a target host, host group, or locally 
  (no target required)
- Passing extra vars (survey variables) at runtime
- Syntax checking before execution
- Visual graph generation via ansible-playbook-grapher
- Playbook dry run mode
- Reusable **Playbook Templates**, which save a playbook path together 
  with a target, extra vars, and secrets for quick, repeatable launches

Ansible Collections (via ansible-galaxy) can be installed, updated, and 
removed directly in the GUI. Collections that are part of the system's 
base installation are shown separately as read-only and are not managed 
through NetPAC.

## Credentials & Scheduling

Credentials can be stored encrypted in the Secrets section and are 
injected into scripts and playbooks at runtime as environment variables.

Scripts can be scheduled with cron expressions (hourly, daily, weekly, 
or custom) via the Scheduler. Each schedule supports targets, variables, 
and secrets.

## Job queue

Jobs are started by a separate service, **netpac-executor**. Every job is first
placed in a queue (status **queued**) and started as soon as a slot is free. By
default up to 5 jobs run in parallel; this can be changed with
`MAX_PARALLEL_JOBS` in secret.env.

A host is only used by one job at a time, no matter which script or playbook.
The check uses the actual hosts behind the target: an update playbook can run
against the group *routers* and the group *switches* in parallel, but if both
targets contain the same host, or another playbook is already running on one of
those hosts, the job waits until the host is free. Jobs without hosts (no target
or localhost) only wait for a running job of the same script or playbook. Queued jobs can be removed from the queue on the job detail page.
A schedule is skipped if its previous run is still waiting in the queue.

Jobs running longer than 4 hours are stopped and get the status **timeout**.
Up to 10 MB of output is stored per job; for larger output the beginning and
the end are kept.

## Hosts

Hosts can be created, edited, and deleted in the GUI and assigned to 
multiple groups.

## Monitoring & Logs

<p align="center">
  <img src="docs/screenshots/job-output.png" alt="Live output of a running Ansible playbook in NetPAC" width="900">
</p>

The output of scripts and playbooks can be viewed in the job history and 
exported as TXT. Running jobs can be cancelled from the job detail page; 
they are then shown with the status **cancelled**. Jobs whose process 
disappeared (e.g. after a NetPAC restart) are marked as **failed**. System logs can be viewed directly in the Settings area. 
A Health page shows the status of the database, scheduler, job executor, 
encryption, venv, and Ansible Galaxy collections at a glance.

Jobs are kept in the history for 180 days; older finished jobs are deleted
automatically once a day by the scheduler. The log files in /var/log/netpac are
rotated weekly and kept for 8 weeks (logrotate, set up by setup.sh).

The UI supports a dark and light mode.

The following explains the steps required to install NetPAC.

## Database configuration

Passwords in user table are stored as bcrypt hashes.
In my setup, I use a mariadb, but a mysql database can also be used.

Here is a prepared configuration to install and create the database.

Install mariadb:

```bash
sudo apt update
sudo apt install mariadb-server -y
```

Start mariadb and add to autostart:

```bash
sudo systemctl start mariadb
sudo systemctl enable mariadb
sudo systemctl status mariadb
```

If you'd like, you can secure a new MariaDB/MySQL installation by following the steps after running the command. This is entirely optional and, among other things, removes anonymous users and the test database:

```bash
sudo mariadb-secure-installation
```

Login as root:

```bash
sudo mariadb -u root -p
```

Start the netpac_db installation. But first, fill in the fields marked with # at the beginning in three places; you'll need to remove the # symbols to do so.:

```sql
CREATE DATABASE IF NOT EXISTS `netpac_db` 
DEFAULT CHARACTER SET utf8mb4 
COLLATE utf8mb4_bin;

CREATE USER '#YOUR-USER#'@'localhost' IDENTIFIED BY '#YOUR-PASSWORD#';

GRANT ALL PRIVILEGES ON netpac_db.* TO '#YOUR-USER#'@'localhost';

FLUSH PRIVILEGES;
```

The tables are created automatically when NetPAC starts for the first time.
Later database changes are applied the same way on every start (database migrations,
see `database/migrations`). Before changing an existing database, NetPAC creates a backup
in the `netpac_backups` folder. The current state can be checked with:

```Bash
python3 netpac_migrations.py
```

## NetPAC configuration

Create a new user and install git.
```Bash
sudo -i
adduser netpac 
apt install git
```

The user must be listed in the sudoers file to create the system service in the setup script.
```Bash
usermod -aG sudo netpac
```

Create a new user directory and clone git.
```Bash
su - netpac
mkdir bin
cd bin/
git clone https://github.com/JimPeterle/NetPAC.git
cd NetPAC
```

The user `netpac` and the directory `~/bin/NetPAC` are the recommended layout, 
but not required: all services run as the user that executes `setup.sh`, from 
the directory it is executed in. Database backups are stored next to the 
application directory (e.g. `~/bin/netpac_backups`).

Create your configuration from the template and fill in the values. 
secret.env is excluded from Git, so later updates via `git pull` never 
overwrite it.

```Bash
cp secret_examples.env secret.env
vim secret.env
```

Generate the ENCRYPTION_KEY (encrypts the stored secrets, tokens and TOTP secrets in the database):
```Bash
sudo apt install python3-cryptography
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Keep a backup of secret.env. Without the ENCRYPTION_KEY, the stored secrets 
can no longer be decrypted (Store the keys inside a Keepass).

### Lost or changed ENCRYPTION_KEY

The TOTP secrets of all users are encrypted with the ENCRYPTION_KEY as well. If the key is lost
or changed, **nobody can log in anymore** (including `admin`): the login shows
"Your two-factor secret can't be read on the server" and `netpac.log` contains a CRITICAL entry
"Cannot decrypt TOTP secret".

To regain access, reset the TOTP of the affected user in the database. On the next login,
a new QR code is shown and TOTP is set up again:
```sql
UPDATE user SET totp_secret = NULL, totp_confirmed = FALSE, totp_last_counter = NULL WHERE name = 'admin';
```

Everything else encrypted with the old key is lost as well and has to be entered again:
the passwords of all Secrets, the Git access token, the RADIUS shared secret and the
SMTP password / Matrix token of the notifications.

When everything is ready, the final step can be carried out.
```Bash
bash setup.sh
```

## Frontend libraries

NetPAC loads nothing from the internet: all frontend libraries (anime.js, 
highlight.js, Chart.js, flatpickr, github-markdown-css) and the JetBrains Mono 
font are stored in `static/vendor/`. This also works in management networks 
without internet access and transfers no user data to third parties.

The versions are defined in `static/vendor/manifest.json`. To update them:

Show available updates (changes nothing):
```Bash
python3 update_vendor.py
```

Update all libraries to their latest release. The new version is downloaded,
`static/vendor/manifest.json` is updated and the old version is removed.
If a download fails, the library stays on its current version.
```Bash
python3 update_vendor.py --update
```

New major versions (e.g. 4.x -> 5.x) are skipped, as they may break NetPAC.
Check the changelog first, then install them explicitly, optionally only for
single libraries:
```Bash
python3 update_vendor.py --update --major chartjs
```

Restart NetPAC afterwards (`sudo systemctl restart netpac`), because the
manifest is read at startup.

Each library keeps its license file in its own folder under `static/vendor/`.

## Additional information

For all users who need to create scripts:
``` Bash
sudo usermod -aG netpacscript <user>
```

If you want to update NetPac run the script:
``` Bash
bash update_netpac.sh
```

## Remove Netpac

If you want to remove netpac do these steps as netpac user:
``` Bash
bash uninstall.sh
```

Then as root:
``` Bash
sudo pkill -u netpac
sudo deluser netpac sudo
sudo deluser --remove-home netpac
```
After this steps netpac is removed from your system.

## License

NetPAC is released under the MIT License: use, copy, modify and distribute it for any
purpose, as long as the license text is included. See [LICENSE](LICENSE).

The third-party libraries and fonts in `static/vendor` keep their own licenses
(their license files are included in each folder).