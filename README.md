# NetPAC - Network Automation Platform

NetPAC is an network management platform, you can create an inventory of hosts and groups and use this inventory for Python scripts.

For login, you can use radius or a local user created in the database.

To update the installed Python modules, you can perform an update under Settings. This will update all modules in the venv. If you want to update NetPAC completely, there is a Bash script called update_git.sh that downloads the latest version from GitHub and updates the venv at the same time. However, this can only be executed via the CLI; it is not yet integrated into the GUI.

All scripts located under **/var/lib/netpac/scripts** are displayed in the GUI and can also be executed there. It is recommended to simply set up the folder as a local Git and then integrate it using VS Code, for example. This eliminates the need for commands on the CLI. 

Hosts can be created and deleted in the GUI. 
In the Settings area, you can view the system logs.

The output of the scripts can be exported as PDF.

The following explains the steps required to install NetPAC.

## Database configuration

Passwords in user table are stored as bcrypt hashes.
In my setup, I use a mariadb, but a mysql database can also be used.

Here is a prepared configuration to create the database.

```sql

-- Create Database
CREATE DATABASE IF NOT EXISTS `netpac_db` 
DEFAULT CHARACTER SET utf8mb4 
COLLATE utf8mb4_bin;

USE `netpac_db`;

-- Create hosts table
CREATE TABLE `hosts` (
  `hostname` VARCHAR(50) NOT NULL,
  `host_group` VARCHAR(20) NOT NULL,
  `description` VARCHAR(50) DEFAULT NULL,
  PRIMARY KEY (`hostname`, `host_group`)
) ENGINE=InnoDB 
DEFAULT CHARSET=utf8mb4 
COLLATE=utf8mb4_bin;

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
  PRIMARY KEY (`job_id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_status` (`status`),
  KEY `idx_started` (`started_at`)
) ENGINE=InnoDB 
AUTO_INCREMENT=1 
DEFAULT CHARSET=utf8mb4 
COLLATE=utf8mb4_bin;

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
  PRIMARY KEY (`job_id`),
  KEY `idx_user` (`user_id`)
) ENGINE=InnoDB 
AUTO_INCREMENT=1 
DEFAULT CHARSET=utf8mb4 
COLLATE=utf8mb4_bin;

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
  `encrypted_password` TEXT NOT NULL,
  `description` TEXT,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB 
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_bin;

-- Create apscheduler table
CREATE TABLE apscheduler_jobs (
    id VARCHAR(191) NOT NULL,
    next_run_time DOUBLE DEFAULT NULL,
    job_state BLOB NOT NULL,
    PRIMARY KEY (id),
    KEY ix_apscheduler_jobs_next_run_time (next_run_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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

In the section “CONFIGURATION – ADJUST HERE!”, you must add your path for the certificate and domain.
```Bash
vim setup.sh
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

If you want do remov netpac do this steps as netpac user:
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