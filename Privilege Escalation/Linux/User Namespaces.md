---
title: "User Namespaces"
created: 2026-11-15
type: concept
tags: [linux, kernel, containers, namespaces, concept]
---

# User Namespaces

A **namespace** gives a process its own isolated view of a system resource. Linux has several types:

| Namespace | Isolates |
|-----------|----------|
| PID | Process IDs — process sees its own PID tree |
| Network | Network stack — own interfaces, routes, firewall |
| Mount | Filesystem mounts |
| User | User/group IDs |
| UTS | Hostname |
| IPC | Inter-process communication |

The important one for exploitation: **user namespaces**.

---

## How User Namespaces Work

Any unprivileged user can create a user namespace. Inside it, they're mapped to **UID 0 (root)**. This "fake root" gets real kernel capabilities — but only within the namespace.

```bash
# As regular user (uid=1000)
$ unshare --user --net --map-root-user

# Now inside the namespace
# id
uid=0(root) gid=0(root)

# This "root" can:
#   - Create network interfaces (CAP_NET_ADMIN)
#   - Configure IPsec/XFRM
#   - Set up firewall rules
#   - Bind to privileged ports
#
# This "root" CANNOT:
#   - Read /root/ on the host
#   - Kill host processes
#   - Mount host filesystems
#   - Modify files owned by real root
```

The capabilities are scoped to the namespace. The kernel tracks that this UID 0 maps to the host's UID 1000, and blocks any operation that would affect the real host.

---

## Why Attackers Use Them

Many kernel subsystems require capabilities like `CAP_NET_ADMIN` to configure. Without user namespaces, only real root can do this — making exploitation pointless (you're already root).

User namespaces break that chicken-and-egg problem:

```
Without namespaces:
  Need root to set up exploit → but exploit gives root → useless

With namespaces:
  Create namespace as regular user → get CAP_NET_ADMIN →
  set up the exploit → corrupt something global (like page cache) →
  exit namespace → trigger corruption on the host → real root
```

The key insight: some resources like the **page cache** are **global** — shared across all namespaces. A process inside a namespace can corrupt them, exit the namespace, and the corruption is still there on the host.

---

## Container Implications

Containers use namespaces for isolation. **Rootless** container runtimes (rootless Docker, Podman) let unprivileged users run containers by creating user namespaces. This means:

- A process inside a rootless container has all the capabilities needed for namespace-based kernel exploits
- The page cache is shared between the container and the host
- No special container privileges (like `--privileged`) are needed
- Multi-tenant Kubernetes clusters, shared CI runners, and any host running rootless containers are exposed

This is why kernel privilege escalation CVEs that use namespaces are especially dangerous in container environments.

---

## Disabling User Namespaces

Some hardened systems disable unprivileged user namespace creation:

```bash
# Check if unprivileged namespaces are allowed
sysctl kernel.unprivileged_userns_clone
# 1 = allowed (default on most distros), 0 = blocked

# Disable (requires root)
sudo sysctl -w kernel.unprivileged_userns_clone=0
```

This breaks rootless containers and some sandboxing (Chromium, Firefox), so it's a tradeoff. But it blocks an entire class of kernel exploits that rely on namespace capabilities.

---

## Related Notes

- [[Page Cache]]
- [[Fragnesia Page Cache Corruption]]
