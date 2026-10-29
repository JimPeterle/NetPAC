# Installation with setup.sh

This installs NetPAC directly on the server: three systemd services (`netpac-web`,
`netpac-scheduler`, `netpac-executor`), nginx as reverse proxy and the `netpac` command.
For the Docker variant see [install-docker.md](install-docker.md).

**Requirements:** Ubuntu or Debian server with sudo, MariaDB (installed below), free ports 80 and 443.

Steps 1 and 2 are needed for the Docker installation as well.

## 1. Prepare the server

NetPAC runs as its own user `netpac`. Create it as root:

```bash
sudo -i
adduser netpac
usermod -aG sudo netpac
```

The user needs sudo rights: `setup.sh` creates the system services with them, and the `netpac`
command uses them to restart the services.

## 2. Create the database

Install MariaDB and start it automatically:

```bash
sudo apt update
sudo apt install mariadb-server -y
sudo systemctl enable --now mariadb
```

<details>
<summary>Optional: secure the MariaDB installation</summary>

`mariadb-secure-installation` removes anonymous users and the test database, among other things:

```bash
sudo mariadb-secure-installation
```
</details>

Log in as root and create the database and its user. Replace `#YOUR-USER#` and `#YOUR-PASSWORD#`
(including the `#`):

```bash
sudo mariadb -u root -p
```

```sql
CREATE DATABASE IF NOT EXISTS `netpac_db`
DEFAULT CHARACTER SET utf8mb4
COLLATE utf8mb4_bin;

CREATE USER '#YOUR-USER#'@'localhost' IDENTIFIED BY '#YOUR-PASSWORD#';
GRANT ALL PRIVILEGES ON netpac_db.* TO '#YOUR-USER#'@'localhost';
FLUSH PRIVILEGES;
```

No schema has to be imported: NetPAC creates the tables on its first start and applies later
database changes automatically (see [Database migrations](operation.md#database-migrations)).

## 3. Download NetPAC

Switch to the user `netpac`, install git and clone NetPAC:

```bash
su - netpac
sudo apt install git
mkdir bin && cd bin
git clone https://github.com/JimPeterle/NetPAC.git
cd NetPAC
```

The user `netpac` and the folder `~/bin/NetPAC` are the recommended layout, but not required:
all services run as the user that executes `setup.sh`, from the folder NetPAC was cloned to.
Database backups are stored next to it (e.g. `~/bin/netpac_backups`).

## 4. Configure

Create the configuration from the template. `config/secret.env` is excluded from Git, so updates
never overwrite it.

```bash
cp config/secret_examples.env config/secret.env
vim config/secret.env
```

Enter the database user and password from step 2. Generate the `ENCRYPTION_KEY` — it encrypts
the stored secrets, tokens and TOTP secrets in the database:

```bash
sudo apt install python3-cryptography
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

> [!WARNING]
> Keep a backup of `config/secret.env`, e.g. in a password manager. Without the `ENCRYPTION_KEY`
> the stored secrets can no longer be decrypted and nobody can log in
> (see [Lost or changed ENCRYPTION_KEY](troubleshooting.md#lost-or-changed-encryption_key)).

## 5. Install

```bash
bash maintenance/setup.sh
```

`setup.sh` asks for the server IP and the number of web workers (2 × CPU cores + 1). It installs
the packages, creates the folders, the systemd services, a self-signed certificate, the nginx
configuration and the `netpac` command.

## After the installation

- Open `https://<server IP>` and log in with **admin** / **admin**. Set up TOTP and then change
  the password under **Settings → User** (see [configuration.md](configuration.md#login-and-two-factor-authentication)).
- Upload your own certificate under **Settings → SSL/TLS** if needed.
- Users who should create scripts directly on the server need the group `netpacscript`:
  ```bash
  sudo usermod -aG netpacscript <user>
  ```
- Check the services with `netpac status` — all commands are listed in [operation.md](operation.md#the-netpac-command).
