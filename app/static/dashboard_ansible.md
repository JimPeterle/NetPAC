## Playbook directory

Store your local Ansible Playbooks here:

**/var/lib/netpac/playbooks/local**

Remote Playbooks over git, they will be stored here. Please don't put here any local Playbooks:

**/var/lib/netpac/git**

## Inventory

Hosts from your inventory are automatically passed to Ansible as a dynamic inventory under the group **[targets]**.

The inventory contains only the hosts of your target (e.g. `r5,routers,switches`), so `hosts: targets` and
`hosts: all` are identical in NetPAC. Prefer `targets`: run elsewhere with a full inventory, `all` would hit every device.

Each host is also listed in its own groups, so a playbook can contain plays for single groups:

```
- hosts: targets
- hosts: routers
- hosts: switches
```

## Storing data between runs

Playbooks can keep files between runs in the folder from `NETPAC_DATA_DIR` (**/var/lib/netpac/data**) on the
NetPAC server, e.g. a config backup. Write to it with `delegate_to: localhost`:

```
- name: Save the running config on the NetPAC server
  ansible.builtin.copy:
    content: "{{ config.stdout[0] }}"
    dest: "{{ lookup('env', 'NETPAC_DATA_DIR') }}/{{ inventory_hostname }}.cfg"
  delegate_to: localhost
```

## Variables

Enter variables for a run as Extra Vars, one per line in the format `Key=Value`. Your own variables and
Ansible's connection variables go into the same field:

```
Version=12
Env=prod
ansible_connection=network_cli
ansible_network_os=cisco.nxos
ansible_port=22
```

In the Playbook, use your own variables like this: `{{ Version }}`.

The **Extra Vars** field is available when you run a Playbook, in schedules and in templates. A schedule or
template saves the values and uses them at every run.

Do not enter passwords here — use **Secrets** instead (see below). Values of variables whose name contains
e.g. `password`, `secret` or `token`, or ends in `_pass`, are hidden in the job history, but Secrets are the
safer place for credentials.

## Survey fields

Survey fields belong to a **template**. You define them once under **Templates**, and NetPAC asks for the
values every time the template is launched. This way, others can start a Playbook without knowing its variables.

The value is passed to the Playbook as a variable with the name of the field. A field named `version`:

```
- name: Show the version
  ansible.builtin.debug:
    msg: "Installing {{ version }}"
```

- A survey value overrides an Extra Var of the template with the same name.
- Values of password fields are hidden in the job history.
- Scheduled runs can't ask anyone, so they use the default values. A template with a required field without
  a default value, or with a required password field, can't be selected for a schedule. If a template is changed
  this way later, its existing schedules stay active but their runs are skipped until the template is fixed.

## Forks

Forks set how many hosts Ansible works on at the same time. With 12 hosts and 5 forks, each task runs on
5 hosts at once until all 12 are done. Set them when starting a playbook, in a template or in a schedule
(1–100). Empty uses the Ansible default of 5, or `forks` from an `ansible.cfg` next to the playbook.

More forks are faster but need more memory and CPU on the NetPAC server.

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

To log in to the hosts with a secret, assign it to Ansible's login variables in the Playbook:

```
  vars:
    ansible_user: "{{ lookup('env', 'SECRET_1_USERNAME') }}"
    ansible_password: "{{ lookup('env', 'SECRET_1_PASSWORD') }}"
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
