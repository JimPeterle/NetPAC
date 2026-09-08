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

Credentials are injected as environment variables:

```
  vars:
    secret_1_username: "{{ lookup('env', 'SECRET_1_USERNAME') }}"
    secret_1_password: "{{ lookup('env', 'SECRET_1_PASSWORD') }}"
    secret_2_username: "{{ lookup('env', 'SECRET_2_USERNAME') }}"
    secret_2_password: "{{ lookup('env', 'SECRET_2_PASSWORD') }}"
    secret_3_username: "{{ lookup('env', 'SECRET_3_USERNAME') }}"
    secret_3_password: "{{ lookup('env', 'SECRET_3_PASSWORD') }}"
```