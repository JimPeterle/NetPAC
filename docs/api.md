# REST API

The API lets scripts and other tools manage the **inventory**: view, create, change and delete
**hosts** and **groups**. Nothing else is reachable through it — no jobs, schedules, secrets,
templates or settings.

## API tokens

- Users with the role **Operator** or **Admin** can use the API. Viewers and the local user `admin`
  can't, not even with a token. Admins can do the same through the API as operators: only hosts and
  groups.
- An **admin** creates tokens for every operator and admin, an **operator** creates tokens for
  themselves — both under **Settings → User → API tokens**.
- Every token gets a name (e.g. "inventory sync") and starts with `nppat-` (NetPAC personal access
  token), so it can be recognised — also by secret scanners — if it ends up in a file or log.
- A token is valid for 30, 90 or 365 days. It is shown **only once**, right after creating it; NetPAC
  only stores a hash of it and can't show it again. The list shows its name, its first characters,
  the expiry date and when it was last used. Delete a token there to revoke it.
- Tokens are deleted when their user is deleted or becomes a viewer.
- Every change made through the API is recorded in the audit log under the token's user, with the
  name of the token.

Send the token in the `Authorization` header:

```bash
export NETPAC_TOKEN="nppat-…"
curl -H "Authorization: Bearer $NETPAC_TOKEN" https://netpac.example.com/api/v1/hosts
```

With the self-signed certificate of a new installation, add `--cacert <certificate>` (or `-k` for a
quick test).

## Endpoints

All requests and responses use JSON. Hosts are addressed by hostname, groups by name.

| Method | Path | Does |
|---|---|---|
| `GET` | `/api/v1/hosts` | List all hosts; `?group=core` only the hosts of one group |
| `POST` | `/api/v1/hosts` | Create a host |
| `GET` | `/api/v1/hosts/<hostname>` | Show one host |
| `PATCH` | `/api/v1/hosts/<hostname>` | Change a host (only the fields you send) |
| `DELETE` | `/api/v1/hosts/<hostname>` | Delete a host |
| `GET` | `/api/v1/groups` | List all groups with their variables and hosts |
| `POST` | `/api/v1/groups` | Create a group |
| `GET` | `/api/v1/groups/<name>` | Show one group |
| `PATCH` | `/api/v1/groups/<name>` | Replace the Ansible variables of a group |
| `DELETE` | `/api/v1/groups/<name>` | Delete a group (its hosts stay, they only leave the group) |

### Host

```json
{
  "id": 12,
  "hostname": "core-sw01.example.com",
  "description": "Core switch",
  "is_active": true,
  "groups": ["core", "switches"]
}
```

| Field | Create (`POST`) | Change (`PATCH`) |
|---|---|---|
| `hostname` | required | renames the host |
| `description` | optional, default empty | |
| `groups` | optional, list of existing group names | replaces all groups; `[]` removes them |
| `is_active` | optional, default `true` | `false` deactivates the host |

### Group

```json
{
  "id": 3,
  "name": "core",
  "ansible_vars": {"ntp_server": "10.0.0.1", "ansible_user": "netops"},
  "hosts": ["core-sw01.example.com"]
}
```

| Field | Create (`POST`) | Change (`PATCH`) |
|---|---|---|
| `name` | required: letters, digits and `_` | can't be changed |
| `ansible_vars` | optional object; values are strings, numbers or `true`/`false` | replaces all variables |

`hosts` is read-only — assign hosts to a group through the host's `groups`.

## Examples

```bash
API=https://netpac.example.com/api/v1
AUTH="Authorization: Bearer $NETPAC_TOKEN"

# Create a group and a host in it
curl -X POST -H "$AUTH" -H "Content-Type: application/json" \
     -d '{"name": "core", "ansible_vars": {"ntp_server": "10.0.0.1"}}' "$API/groups"
curl -X POST -H "$AUTH" -H "Content-Type: application/json" \
     -d '{"hostname": "core-sw01", "description": "Core switch", "groups": ["core"]}' "$API/hosts"

# Deactivate the host
curl -X PATCH -H "$AUTH" -H "Content-Type: application/json" -d '{"is_active": false}' "$API/hosts/core-sw01"

# Delete it
curl -X DELETE -H "$AUTH" "$API/hosts/core-sw01"
```

Python:

```python
import os
import requests

api = "https://netpac.example.com/api/v1"
headers = {"Authorization": f"Bearer {os.environ['NETPAC_TOKEN']}"}

for host in requests.get(f"{api}/hosts", headers=headers, params={"group": "core"}).json():
    print(host["hostname"], host["is_active"])
```

## Responses and errors

| Status | Meaning |
|---|---|
| `200` / `201` | OK / created; the body is the host or group |
| `204` | Deleted |
| `400` | Invalid request; `error` says what is wrong |
| `401` | Token missing, unknown or expired |
| `403` | The token's user may not use the API (anymore) |
| `404` | Host or group not found |
| `409` | A host or group with this name already exists |
| `429` | More than 120 requests per minute to one endpoint from one address |

Errors always come as `{"error": "…"}`.
