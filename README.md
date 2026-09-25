# NetPAC - Network Python & Ansible Center

NetPAC is a network automation and management platform. You can create an inventory of 
hosts and groups and use this inventory for Python scripts and Ansible 
Playbooks.

For login, you can use RADIUS or a local user. All users are required to 
set up two-factor authentication (TOTP) on first login.

For local login you can use for first startup the user **admin** with password **admin**, after login and totp verification please change the default password under Settings -> Change Password of local user. 
If you logged in with the local admin user, you can add more local user. 

For RADIUS login, the local admin configures the RADIUS server under 
Settings -> Radius. The shared secret is stored encrypted in the database.

setup.sh creates a self-signed SSL certificate. Your own certificate 
(e.g. from Let's Encrypt or an internal CA) can be uploaded later under 
Settings -> SSL/TLS.

## Scripts

All scripts located under **/var/lib/netpac/scripts** are displayed in the 
GUI and can be executed there. Scripts can also be synced directly from 
a Git repository via the built-in Git Sync feature in the UI.

## Ansible Playbooks

All playbooks located under **/var/lib/netpac/playbooks** are displayed 
in the GUI and can be executed there. Playbooks can also be synced 
directly from a Git repository — Scripts and Playbooks share the same 
Git sync target, so both are updated with a single sync.

Playbooks support:
- Browsing folders and subfolders
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

A Python virtual environment (venv) is available for scripts and can be 
managed directly in the GUI (install, update, remove packages).

## Credentials & Scheduling

Credentials can be stored encrypted in the Secrets section and are 
injected into scripts and playbooks at runtime as environment variables.

Scripts can be scheduled with cron expressions (hourly, daily, weekly, 
or custom) via the Scheduler. Each schedule supports targets, variables, 
and secrets.

## Hosts

Hosts can be created, edited, and deleted in the GUI and assigned to 
multiple groups.

## Monitoring & Logs

The output of scripts and playbooks can be viewed in the job history and 
exported as TXT. Running jobs can be cancelled from the job detail page; 
they are then shown with the status **cancelled**. Jobs whose process 
disappeared (e.g. after a NetPAC restart) are marked as **failed**. System logs can be viewed directly in the Settings area. 
A Health page shows the status of the database, scheduler, encryption, 
venv, and Ansible Galaxy collections at a glance.

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
sudo mysql_secure_installation
```

Login as root:

```bash
sudo mysql -u root -p
```

Start the netpac_db installation:

```sql
CREATE DATABASE IF NOT EXISTS `netpac_db` 
DEFAULT CHARACTER SET utf8mb4 
COLLATE utf8mb4_bin;

CREATE USER 'YOUR-USER'@'localhost' IDENTIFIED BY 'YOUR-PASSWORD';

GRANT ALL PRIVILEGES ON netpac_db.* TO 'YOUR-USER'@'localhost';

FLUSH PRIVILEGES;

USE `netpac_db`;

CREATE TABLE `hosts` (
    host_id INT AUTO_INCREMENT PRIMARY KEY,
    hostname VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB 
AUTO_INCREMENT=1 
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `host_groups` (
    group_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    ansible_vars TEXT DEFAULT NULL
) ENGINE=InnoDB 
AUTO_INCREMENT=1 
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `host_group_membership` (
    host_id INT NOT NULL,
    group_id INT NOT NULL,
    PRIMARY KEY (host_id, group_id),
    FOREIGN KEY (host_id) REFERENCES hosts(host_id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES host_groups(group_id) ON DELETE CASCADE
) ENGINE=InnoDB 
AUTO_INCREMENT=1 
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `history_jobs` (
  `job_id` INT(11) NOT NULL AUTO_INCREMENT,
  `script_name` VARCHAR(255) NOT NULL,
  `user_id` VARCHAR(100) NOT NULL,
  `target` VARCHAR(255) DEFAULT NULL,
  `variables` LONGTEXT DEFAULT NULL,
  `status` ENUM('running','planned','completed','failed','timeout','cancelled') DEFAULT 'running',
  `output` LONGTEXT DEFAULT NULL,
  `started_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP(),
  `finished_at` TIMESTAMP NULL DEFAULT NULL,
  `duration` INT(11) DEFAULT NULL,
  `credential` TEXT DEFAULT NULL,
  `job_type` ENUM('python','ansible') DEFAULT 'python',
  `ansible_dry_run` TINYINT(1) DEFAULT 0,
  `pid` INT DEFAULT NULL,
  PRIMARY KEY (`job_id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_status` (`status`),
  KEY `idx_started` (`started_at`),
  KEY `idx_history_script_name` (`script_name`),
  KEY `idx_history_job_type` (`job_type`)
) ENGINE=InnoDB 
AUTO_INCREMENT=1 
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `schedule_jobs` (
  `job_id` INT(11) NOT NULL AUTO_INCREMENT,
  `script_name` VARCHAR(255) NOT NULL,
  `user_id` VARCHAR(100) NOT NULL,
  `target` VARCHAR(255) DEFAULT NULL,
  `variables` LONGTEXT DEFAULT NULL,
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `schedule_expression` VARCHAR(100) NOT NULL,
  `credential` TEXT DEFAULT NULL,
  `use_venv` TINYINT(1) DEFAULT 0,
  `job_type` VARCHAR(20) DEFAULT 'python',
  PRIMARY KEY (`job_id`),
  KEY `idx_user` (`user_id`)
) ENGINE=InnoDB 
AUTO_INCREMENT=1 
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `playbook_templates` (
  `template_id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(255) NOT NULL,
  `description` TEXT,
  `playbook_path` VARCHAR(500) NOT NULL,
  `target` VARCHAR(255),
  `extra_vars` TEXT,
  `secret_1` VARCHAR(255),
  `secret_2` VARCHAR(255),
  `secret_3` VARCHAR(255),
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `created_by` VARCHAR(255)
) ENGINE=InnoDB
AUTO_INCREMENT=1
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `user` (
  `name` VARCHAR(100) NOT NULL,
  `password` VARCHAR(255) DEFAULT NULL,
  `totp_secret` VARCHAR(32) DEFAULT NULL,
  `totp_confirmed` BOOLEAN DEFAULT FALSE,
  `method` VARCHAR(10) DEFAULT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB 
DEFAULT CHARSET=utf8mb4 
COLLATE=utf8mb4_bin;

INSERT INTO `user` (`name`, `password`, `method`) VALUES (
  'admin',
  '$2b$12$3u9Sfbazd4cOpm9kEKspyO7aU0R0BnND.mo5JBTYH8QSmtIj.rk82',
  'local'
);

CREATE TABLE IF NOT EXISTS `secrets` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(100) UNIQUE NOT NULL,
  `username` VARCHAR(100) NOT NULL,
  `encrypted_password` TEXT NOT NULL COLLATE utf8mb4_bin,
  `description` TEXT,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB
AUTO_INCREMENT=1
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;

CREATE TABLE apscheduler_jobs (
    id VARCHAR(191) NOT NULL,
    next_run_time DOUBLE DEFAULT NULL,
    job_state BLOB NOT NULL,
    PRIMARY KEY (id),
    KEY ix_apscheduler_jobs_next_run_time (next_run_time)
) ENGINE=InnoDB 
AUTO_INCREMENT=1
DEFAULT CHARSET=utf8mb4;

CREATE TABLE radius(
    id INT PRIMARY KEY DEFAULT 1,
    server VARCHAR(255),
    port INT DEFAULT 1812,
    encrypted_secret TEXT,
    timeout INT DEFAULT 5,
    CONSTRAINT single_row CHECK (id = 1)
);
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
but not required: both services run as the user that executes `setup.sh`, from 
the directory it is executed in. Database backups are stored next to the 
application directory (e.g. `~/bin/netpac_backups`).

Create your configuration from the template and fill in the values. 
secret.env is excluded from Git, so later updates via `git pull` never 
overwrite it.

```Bash
cp secret_examples.env secret.env
vim secret.env
```

Generate the ENCRYPTION_KEY (encrypts the stored secrets in the database):
```Bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Keep a backup of secret.env. Without the ENCRYPTION_KEY, the stored secrets 
can no longer be decrypted (Store the keys inside a Keepass).

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
```Bash
python3 update_vendor.py --check   # show available updates
# change the version in static/vendor/manifest.json
python3 update_vendor.py           # download the new version, remove the old one
```
Each library keeps its license file in its own folder under `static/vendor/`.

## Additional information

For all users who need to create scripts:
``` Bash
sudo usermod -aG netpacscript <user>
```

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

Copyright (C) 2026 JimPeterle

NetPAC is free software: you can redistribute it and/or modify it under the 
terms of the GNU Affero General Public License as published by the Free 
Software Foundation, either version 3 of the License, or (at your option) 
any later version. See [LICENSE](LICENSE) for the full text.

In short: you may use, modify and share NetPAC, also commercially. If you 
distribute a modified version or make it available to others over a network, 
you must publish its complete source code under the same license.

The libraries in `static/vendor/` keep their own licenses (MIT, BSD-3-Clause, 
SIL Open Font License); each license file is stored next to the library.
