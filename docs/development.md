# Development

## Repository layout

| Folder | Content |
|---|---|
| `app/` | NetPAC itself: web interface (`netpac.py`), scheduler, executor, database migrations (`db_migrations.py`), templates, static files |
| `config/` | `secret_examples.env` (template), the RADIUS dictionary; locally also `secret.env`, `db_secrets.cnf`, `git_config.json` (not in Git) |
| `maintenance/` | `setup.sh`, `update_netpac.sh`, `uninstall.sh`, `update_vendor.py` and the `netpac` command |
| `database/migrations/` | Database changes as numbered SQL files, applied automatically on start |
| `docker/` | Dockerfile, docker-compose.yml, entrypoint and Gunicorn configuration of the image |
| `docs/` | This documentation and screenshots |

## Frontend libraries

NetPAC loads nothing from the internet: all frontend libraries (anime.js, highlight.js, Chart.js,
flatpickr, github-markdown-css) and the fonts are stored in `app/static/vendor/`. This also works in
management networks without internet access and transfers no user data to third parties. Each
library keeps its license file in its folder.

The versions are defined in `app/static/vendor/manifest.json`. Update them on your development
machine and commit the result — servers get them with the next update.

```bash
python3 maintenance/update_vendor.py                          # show available updates, changes nothing
python3 maintenance/update_vendor.py --update                 # update all libraries
python3 maintenance/update_vendor.py --update --major chartjs # also a new major version, single library
```

- `--update` downloads the new version, updates `manifest.json` and removes the old version. If a
  download fails, the library stays on its current version.
- New major versions (e.g. 4.x → 5.x) are skipped unless `--major` is given — check the changelog first.
- Restart NetPAC afterwards, because the manifest is read at startup.

## Docker image

The image is built by GitHub Actions (`.github/workflows/docker.yml`) and published as
`ghcr.io/jimpeterle/netpac`:

| Trigger | Built version | Tags |
|---|---|---|
| New tag `v*` | this version | `9.0.1`, `9.0`, `9`, and `latest` if it is the newest version |
| Every Monday 03:00 UTC | the newest release, with current Ubuntu packages | `9.0.1`, `9.0`, `9`, `latest` |
| Manual run | the newest release, or the `main` branch for testing (tag `main`) | as above / `main` |

Build the image locally from the repository root:

```bash
docker build -f docker/Dockerfile -t ghcr.io/jimpeterle/netpac:latest .
```
