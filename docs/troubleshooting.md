# Troubleshooting

## Lost or changed ENCRYPTION_KEY

The TOTP secrets of all users are encrypted with the `ENCRYPTION_KEY`. If the key is lost or changed,
**nobody can log in anymore** (including `admin`):

- the login shows "Your two-factor secret can't be read on the server"
- `netpac.log` contains a CRITICAL entry "Cannot decrypt TOTP secret"

To regain access, reset the TOTP of the affected user in the database. On the next login, a new QR
code is shown and TOTP is set up again:

```sql
UPDATE user SET totp_secret = NULL, totp_confirmed = FALSE, totp_last_counter = NULL WHERE name = 'admin';
```

Everything else encrypted with the old key is lost as well and has to be entered again: the
passwords of all secrets, the Git access token, the RADIUS shared secret and the SMTP password /
Matrix token of the notifications.

## Docker containers don't start

If `docker compose ps` shows a container as `Restarting`, look at its output and at the NetPAC log:

```bash
docker compose logs web --tail 30
tail -n 30 /var/log/netpac/netpac.log
```

| Message contains | Cause |
|---|---|
| `secret.env not found` | `secret.env` is not next to docker-compose.yml |
| `secret.env is not readable for UID …` | `secret.env` belongs to another user than the one NetPAC runs as — `chown netpac:netpac secret.env` |
| `Permission denied` for `/var/log/netpac` or `/var/lib/netpac` | The folders belong to another user — `sudo chown -R netpac:netpac /var/log/netpac /var/lib/netpac /etc/netpac/certs` |
| `secret.env is missing required values` | `ENCRYPTION_KEY`, `FLASK_KEY` or a `DB_*` value is missing |
| `Can't connect to MySQL server` / `Access denied` | MariaDB on the host is not running, or user / password in `secret.env` are wrong |

## `netpac: command not found`

The link to the command is missing. Create it again (adjust the path if NetPAC is somewhere else):

```bash
sudo ln -sf ~/bin/NetPAC/maintenance/netpac /usr/local/bin/netpac
```

## A service doesn't start (installation with setup.sh)

```bash
netpac status
sudo journalctl -u netpac-web -n 50
netpac logs gunicorn_error
```
