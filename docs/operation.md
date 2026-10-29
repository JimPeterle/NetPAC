# Operation

This page covers the installation with `setup.sh`. With Docker, use the commands in
[install-docker.md](install-docker.md#commands).

## The netpac command

`setup.sh` installs the command `netpac` (`/usr/local/bin/netpac`). Run it as the NetPAC user:

| Command | |
|---|---|
| `netpac status` | State of the NetPAC services |
| `netpac start` / `stop` / `restart` | Start, stop or restart all NetPAC services |
| `netpac update` | Update NetPAC (git pull, database changes, restart) |
| `netpac logs [name]` | Follow a log file: `netpac` (default), `execution`, `scheduler`, `gunicorn_error`, `gunicorn_access` |
| `netpac db` | Database migration state (`--apply` applies pending changes now) |
| `netpac version` | NetPAC version and Git commit |
| `netpac uninstall` | Remove NetPAC from the server (asks before every step) |
| `netpac help` | All commands |

## Updates

```bash
netpac update
```

The update pulls the new version, applies database changes (with a backup first) and restarts the
services. Read the release notes before updating to a new major version.

<details>
<summary>Updating from NetPAC 7.x or older</summary>

Older versions don't have the `netpac` command yet. Run the update script from the NetPAC folder
as before:

```bash
bash update_netpac.sh
```

If it stops with "No such file", run the new script once — it moves `secret.env` to `config/`,
updates the services and nginx and installs the `netpac` command:

```bash
bash maintenance/update_netpac.sh
```
</details>

## Job queue

Jobs are started by the service **netpac-executor**:

- Every job is first queued (status **queued**) and starts as soon as a slot is free. Up to 5 jobs
  run in parallel (`MAX_PARALLEL_JOBS` in `app/netpac.py`).
- A host is only used by one job at a time, no matter which script or playbook. The check uses
  the actual hosts behind the target: an update playbook can run against the groups *routers* and
  *switches* in parallel, but if both contain the same host, the second job waits.
- Jobs without hosts (no target or localhost) only wait for a running job of the same script or playbook.
- Queued jobs can be removed from the queue on the job detail page; running jobs can be cancelled
  there (status **cancelled**).
- Jobs running longer than 4 hours are stopped (status **timeout**).
- Up to 10 MB of output is stored per job; for larger output the beginning and the end are kept.
- Restarting `netpac-web` doesn't affect running jobs; restarting `netpac-executor` stops them
  (they are marked as **failed**).

## Job history and logs

- The output of every job is shown live in the job history and can be exported as TXT.
- Jobs are kept for 180 days; older finished jobs are deleted automatically once a day.
- The audit log (**Settings → Audit**) records logins, changes and denied actions and keeps them for 365 days.
- Log files are in `/var/log/netpac`, rotated weekly and kept for 8 weeks. Admins can view them under
  **Settings → Logs**, on the server with `netpac logs`.

## Health page

The **Health** page (admins only) shows the state of the database, scheduler, job executor, queue,
encryption, venv, Ansible, the script and playbook folders and the Git sync at a glance.

## Database migrations

NetPAC creates its tables on the first start and applies later database changes automatically on
every start (`database/migrations`). Before changing an existing database it creates a backup in
`netpac_backups` next to the NetPAC folder. Check the state with:

```bash
netpac db
```

## Backups

Admins create, download, restore and delete database backups under **Settings → Backup**.
Keep a copy of `config/secret.env` as well — a backup is useless without the `ENCRYPTION_KEY`.
