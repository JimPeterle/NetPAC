# NetPAC - Network Python & Ansible Center

NetPAC is a network automation and management platform. You can create an inventory of 
hosts and groups and use this inventory for Python scripts and Ansible 
Playbooks.

For login, you can use RADIUS or a local user. All users are required to 
set up two-factor authentication (TOTP) on first login.

For local login you can use for first startup the user **admin** with password **admin**, after login and totp verification please change the default password under Settings -> Change Password of local user. 
If you logged in with the local admin user, you can add more local user. 

For Radius login please specify the needed parameter in the secret.env.

Before running setup.sh, make sure your SSL certificate and private key 
are in place and specify the needed parameter in the secret.env.

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
exported as TXT. System logs can be viewed directly in the Settings area. 
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

-- Create Database and user
CREATE DATABASE IF NOT EXISTS `netpac_db` 
DEFAULT CHARACTER SET utf8mb4 
COLLATE utf8mb4_bin;

CREATE USER 'YOUR-USER'@'localhost' IDENTIFIED BY 'YOUR-PASSWORD';

GRANT ALL PRIVILEGES ON netpac_db.* TO 'YOUR-USER'@'localhost';

FLUSH PRIVILEGES;
EXIT;

USE `netpac_db`;

-- Create hosts table
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ansible_vars TEXT DEFAULT NULL;
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

-- Create history_jobs table
CREATE TABLE `history_jobs` (
  `job_id` INT(11) NOT NULL AUTO_INCREMENT,
  `script_name` VARCHAR(255) NOT NULL,
  `user_id` VARCHAR(100) NOT NULL,
  `target` VARCHAR(255) DEFAULT NULL,
  `variables` LONGTEXT DEFAULT NULL,
  `status` ENUM('running','planned','completed','failed','timeout') DEFAULT 'running',
  `output` TEXT DEFAULT NULL,
  `started_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP(),
  `finished_at` TIMESTAMP NULL DEFAULT NULL,
  `duration` INT(11) DEFAULT NULL,
  `credential` TEXT DEFAULT NULL,
  `job_type` ENUM('python','ansible') DEFAULT 'python',
  `pid` INT DEFAULT NULL;
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

-- Create schedule_jobs table
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

-- Create playbooks table
CREATE TABLE `playbooks` (
  `playbook_id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(255) NOT NULL,
  `path` VARCHAR(500) NOT NULL,
  `description` TEXT,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB
AUTO_INCREMENT=1
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;

-- Create playbook_templates table
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

-- Create user table
CREATE TABLE `user` (
  `name` VARCHAR(20) NOT NULL,
  `password` VARCHAR(255) DEFAULT NULL,
  `totp_secret` VARCHAR(32) DEFAULT NULL,
  `totp_confirmed` BOOLEAN DEFAULT FALSE,
  `method` VARCHAR(10) DEFAULT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB 
DEFAULT CHARSET=utf8mb4 
COLLATE=utf8mb4_bin;

-- Create admin user
INSERT INTO `user` (`name`, `password`, `method`) VALUES (
  'admin',
  '$2b$12$3u9Sfbazd4cOpm9kEKspyO7aU0R0BnND.mo5JBTYH8QSmtIj.rk82',
  'local'
);

-- Create secret table
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

-- Create apscheduler table
CREATE TABLE apscheduler_jobs (
    id VARCHAR(191) NOT NULL,
    next_run_time DOUBLE DEFAULT NULL,
    job_state BLOB NOT NULL,
    PRIMARY KEY (id),
    KEY ix_apscheduler_jobs_next_run_time (next_run_time)
) ENGINE=InnoDB 
AUTO_INCREMENT=1
DEFAULT CHARSET=utf8mb4;

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

The secret_examples.env file serves as a template.
```Bash
vim secret.env
```

To create an ENCRYPTION_KEY used to encrypt passwords in the database, run the following command and store the key in secret.env.
```Bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

When everything is ready, the final step can be carried out.
```Bash
bash setup.sh
```

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