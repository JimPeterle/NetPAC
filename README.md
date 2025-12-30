# NetPAC - Network Automation Platform

NetPAC is an network management platform, you can create an inventory of hosts and groups and use this inventory for Python scripts.

For login, you can use radius or a local user created in the database.

To update the installed Python modules, you can perform an update under Settings. This will update all modules in the venv. If you want to update NetPAC completely, there is a Bash script called update_git.sh that downloads the latest version from GitHub and updates the venv at the same time. However, this can only be executed via the CLI; it is not yet integrated into the GUI.

All scripts located under **/var/lib/netpac/scripts** are displayed in the GUI and can also be executed there. It is recommended to simply set up the folder as a local Git and then integrate it using VS Code, for example. This eliminates the need for commands on the CLI. 

Hosts can be created and deleted in the GUI. 
In the Settings area, you can view the system logs.

The following explains the steps required to install NetPAC.
## Database configuration
---

Passwords in user table are stored as bcrypt hashes.
In my setup, I use a mariadb, but a mysql database can also be used.

Create a database with the following hierarchy.
```
netpac_db/
├── hosts
│   ├── hostname [PRIMARY KEY]
│   ├── host_group
│   └── host_group_2
│
├── script_jobs
│   ├── job_id [PRIMARY KEY, AUTO_INCREMENT]
│   ├── script_name
│   ├── user_id [INDEXED]
│   ├── target
│   ├── variables [JSON]
│   ├── status [ENUM, INDEXED]
│   ├── output [TEXT]
│   ├── started_at [TIMESTAMP, INDEXED]
│   ├── finished_at [TIMESTAMP]
│   └── duration [INT]
│
└── user
    ├── name [PRIMARY KEY]
    └── password [HASHED]
```

Here is a prepared configuration to create the database.
```sql
-- Create Database
CREATE DATABASE IF NOT EXISTS `netpac_db` 
DEFAULT CHARACTER SET utf8mb3 
COLLATE utf8mb3_bin;

USE `netpac_db`;

-- Create hosts table
CREATE TABLE `hosts` (
  `hostname` VARCHAR(50) NOT NULL,
  `host_group` VARCHAR(20) NOT NULL,
  `host_group_2` VARCHAR(20) NOT NULL,
  PRIMARY KEY (`hostname`)
) ENGINE=InnoDB 
DEFAULT CHARSET=utf8mb3 
COLLATE=utf8mb3_bin;

-- Create script_jobs table
CREATE TABLE `script_jobs` (
  `job_id` INT(11) NOT NULL AUTO_INCREMENT,
  `script_name` VARCHAR(255) NOT NULL,
  `user_id` VARCHAR(100) NOT NULL,
  `target` VARCHAR(255) DEFAULT NULL,
  `variables` LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL 
    CHECK (json_valid(`variables`)),
  `status` ENUM('running','completed','failed','timeout') DEFAULT 'running',
  `output` TEXT DEFAULT NULL,
  `started_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP(),
  `finished_at` TIMESTAMP NULL DEFAULT NULL,
  `duration` INT(11) DEFAULT NULL,
  PRIMARY KEY (`job_id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_status` (`status`),
  KEY `idx_started` (`started_at`)
) ENGINE=InnoDB 
AUTO_INCREMENT=1 
DEFAULT CHARSET=utf8mb3 
COLLATE=utf8mb3_bin;

-- Create user table
CREATE TABLE `user` (
  `name` VARCHAR(20) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB 
DEFAULT CHARSET=utf8mb3 
COLLATE=utf8mb3_bin;
```


## NetPAC configuration
---

Create a new user and install git.
```Bash
sudo -i
adduser netpac 
apt install git
```

The user must be listed in the sudoers file to create the system service in the setup script.
```Bash
usermod -a -G sudo netpac
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

In the section “CONFIGURATION – CUSTOMIZE HERE!”, you must add your path for the certificate and domain.
```Bash
vim setup.sh
```

When everything is ready, the final step can be carried out.
```Bash
bash setup.sh
```


## Additional information
---

For all users who need to create scripts:
``` Bash
sudo usermod -aG netpacscript <user>
```
