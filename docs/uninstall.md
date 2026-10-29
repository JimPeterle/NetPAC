# Remove NetPAC

## Installation with setup.sh

As user `netpac`:

```bash
netpac uninstall
```

The script asks before every step (services, nginx, certificate, logs, data, backups, database,
packages). Then remove the user as root:

```bash
sudo pkill -u netpac
sudo deluser netpac sudo
sudo deluser --remove-home netpac
```

## Docker installation

1. As user `netpac`, in the folder with docker-compose.yml: remove the containers, the Docker volumes
   (Python venv, Ansible collections, SSH known_hosts, Git sync settings) and the images:
   ```bash
   docker compose down --volumes --rmi all
   ```

2. Remove the data on the host. This deletes scripts, playbooks, logs and the certificate:
   ```bash
   sudo rm -rf /var/lib/netpac /var/log/netpac /etc/netpac
   sudo rm -f /etc/logrotate.d/netpac
   ```

3. Remove the database and its user in MariaDB (`sudo mariadb -u root -p`, use the `DB_USER` from secret.env):
   ```sql
   DROP DATABASE IF EXISTS `netpac_db`;
   DROP USER IF EXISTS '#YOUR-USER#'@'localhost';
   ```

4. Remove the folder with docker-compose.yml. It contains `secret.env` with the encryption key and the
   `backups` folder — keep a copy of the backups first if you may need them later:
   ```bash
   cd ~ && rm -rf ~/bin/netpac
   ```

5. Remove the user `netpac` as root:
   ```bash
   sudo pkill -u netpac
   sudo deluser --remove-home netpac
   ```

<details>
<summary>Optional: remove Docker and MariaDB</summary>

Only if nothing else on the server uses them:

```bash
sudo apt remove --purge docker.io docker-compose-v2
sudo apt remove --purge mariadb-server
```
</details>
