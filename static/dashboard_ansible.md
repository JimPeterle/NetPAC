## Playbook directory

Store your local Ansible Playbooks here:

**/var/lib/netpac/playbooks/local**

Remote Playbooks over git, they will be stored here. Please don't put here any local Playbooks:

**/var/lib/netpac/git**

## Inventory

Hosts from your inventory are automatically passed to Ansible as a dynamic inventory under the group **[targets]**.

## Survey variables

Pass extra variables to your Playbook using the Survey field. One variable per line in the format:

```
Version=12
Env=prod
Host=192.168.1.1
```

## Ansible variables

You can also add Ansible Variables in the Survey Variables tab.
For example:

```
ansible_connection=network_cli
ansible_network_os=cisco.nxos
ansible_user=admin
ansible_password=yourpassword
ansible_port=22                      
```

You can also import the Secrets directly like this in the Playbook:

```
vars:
  ansible_user: "{{ lookup('env', 'SECRET_1_USERNAME') }}"
  ansible_password: "{{ lookup('env', 'SECRET_1_PASSWORD') }}"
```

## Secrets

Credentials of type **Username + password** are injected as environment variables:

```
  vars:
    secret_1_username: "{{ lookup('env', 'SECRET_1_USERNAME') }}"
    secret_1_password: "{{ lookup('env', 'SECRET_1_PASSWORD') }}"
    secret_2_username: "{{ lookup('env', 'SECRET_2_USERNAME') }}"
    secret_2_password: "{{ lookup('env', 'SECRET_2_PASSWORD') }}"
    secret_3_username: "{{ lookup('env', 'SECRET_3_USERNAME') }}"
    secret_3_password: "{{ lookup('env', 'SECRET_3_PASSWORD') }}"
```

## SSH keys

Select a secret of type **SSH key** — nothing else is needed in the Playbook.
NetPAC passes it automatically as `--private-key` and its username as `--user`.
The key exists only as a temporary file while the job runs.

- `ansible_user` from group variables or the Playbook takes precedence over the username of the secret.
- Only the first selected SSH key is passed automatically. Further keys are available as files:

```
  vars:
    ansible_ssh_private_key_file: "{{ lookup('env', 'SECRET_2_KEYFILE') }}"
```

The matching public key must be in `~/.ssh/authorized_keys` on the targets
(for network devices: in the device's key configuration, e.g. `ip ssh pubkey-chain` on Cisco IOS).
On the first connection, the host key of the target must be known to the NetPAC user
(`~/.ssh/known_hosts`, e.g. via `ssh-keyscan`).

## Ansible Vault

Select a secret of type **Vault password**. NetPAC passes it as
`--vault-id <secret name>@<temporary file>`, so encrypted variable files and
`!vault` strings in the Playbook are decrypted automatically.

Several vault passwords can be selected at once. To make the assignment explicit,
encrypt with the secret name as vault ID:

```
ansible-vault encrypt_string --vault-id <secret name>@prompt 'my-password' --name 'ansible_password'
```
