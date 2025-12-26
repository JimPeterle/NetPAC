# Instructions

To use the host inventory correctly, the following text block must exist at the beginning of the Python script:

```Python
import os

hostfile_path = os.environ.get('PACMAN_HOSTFILE')

with open(hostfile_path, "r") as h:
    f = h.readlines()
    x = ''.join(f)
```

The variable x can then be used further, for example for Netmiko.
