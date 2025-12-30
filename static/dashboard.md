# Instructions

The scripts should be stored here: /var/lib/netpac/script

## Inventory

To use the host inventory correctly, the following text block must exist at the beginning of the Python script:

```Python
import os

hostfile_path = os.environ.get('NETPAC_HOSTFILE')

with open(hostfile_path, "r") as h:
	f = h.readlines()
	x = ''.join(f)
```

The variable x can then be used further, for example for Netmiko.


## Variables

To use the variables correctly, the following text block must exist at the beginning of the Python script:

```Python

import sys

var1 = sys.argv[1]
var2 = sys.argv[1]
var3 = sys.argv[1]
```

The variable name in the script can be chosen freely.