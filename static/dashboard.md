# Instructions

The scripts should be stored here: /var/lib/netpac/script

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


## Secrets

To use the credentials from the secret tab use this:

```python
import os

username_1 = os.environ.get('SECRET_1_USERNAME')
password_1 = os.environ.get('SECRET_1_PASSWORD')

username_2 = os.environ.get('SECRET_2_USERNAME')
password_2 = os.environ.get('SECRET_2_PASSWORD')

username_3 = os.environ.get('SECRET_3_USERNAME')
password_3 = os.environ.get('SECRET_3_PASSWORD')
```

Then you can use the two variables for further things.