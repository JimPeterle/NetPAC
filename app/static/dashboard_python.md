## Script directory
Store your local Python scripts here:

**/var/lib/netpac/scripts/local**

Remote Scripts over git, they will be stored here. Please don't put here any local Scripts:

**/var/lib/netpac/git**

## Inventory

To use the host inventory correctly, the following text block must exist at the beginning of the Python script:

```python
import os

hostfile_path = os.environ.get('NETPAC_HOSTFILE')

with open(hostfile_path, "r") as h:
    hosts = [line.strip() for line in h.readlines() if line.strip()]
```

The variable hosts can then be used further, for example for Netmiko.


## Variables

To use the variables correctly, the following text block must exist at the beginning of the Python script:

```python
import sys

var1 = sys.argv[1]
var2 = sys.argv[2]
var3 = sys.argv[3]
```

The variable name in the script can be chosen freely.


## Storing data between runs

Scripts that need to remember something between runs (e.g. the last seen version) can store files in
the folder from `NETPAC_DATA_DIR` (**/var/lib/netpac/data**). It is writable for NetPAC and kept across
updates, also with Docker. Don't write into the script or Git folders.

```python
import json
import os
from datetime import datetime
from pathlib import Path

state_file = Path(os.environ["NETPAC_DATA_DIR"]) / "update_checker.json"

state = json.loads(state_file.read_text()) if state_file.exists() else {}
state["last_run"] = datetime.now().isoformat()
state_file.write_text(json.dumps(state, indent=2))
```

Use a file name per script, as all scripts share this folder.


## Secrets

Selected secrets are passed as environment variables, numbered by their slot (1–3).
`SECRET_1_TYPE` tells you the type: `password`, `ssh_key` or `vault_password`.

**Username + password**

```python
import os

username_1 = os.environ.get('SECRET_1_USERNAME')
password_1 = os.environ.get('SECRET_1_PASSWORD')

username_2 = os.environ.get('SECRET_2_USERNAME')
password_2 = os.environ.get('SECRET_2_PASSWORD')
```

**SSH key**

NetPAC writes the private key to a temporary file that only NetPAC can read
and deletes it when the job ends. The key is always passed without passphrase.

```python
import os

username = os.environ.get('SECRET_1_USERNAME')
key_file = os.environ.get('SECRET_1_KEYFILE')
```

Example with Netmiko:

```python
from netmiko import ConnectHandler

connection = ConnectHandler(
    device_type='cisco_ios',
    host=host,
    username=username,
    use_keys=True,
    key_file=key_file,
)
```

Example with Paramiko:

```python
import paramiko

client = paramiko.SSHClient()
client.load_system_host_keys()
client.connect(host, username=username, key_filename=key_file)
```

The matching public key must be in `~/.ssh/authorized_keys` of that user on the target.

**Vault password**

`SECRET_1_VAULTFILE` contains the path to a temporary file with the vault password,
e.g. for scripts that call `ansible-vault` themselves.
