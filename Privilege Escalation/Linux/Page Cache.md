---
title: "Linux Page Cache"
created: 2026-11-15
type: concept
tags: [linux, kernel, memory, concept]
---

# Linux Page Cache

When a process reads a file from disk, the kernel doesn't throw the data away after. It keeps a copy in RAM so the next read is fast. That RAM copy is the **page cache**.

```
Disk:  /usr/bin/su  [permanent, slow]
         |
         v  (first read loads it)
RAM:   page cache   [fast, shared by everyone]
```

Every subsequent read of that file — by any process, any user, any container — comes from the page cache, not from disk. The kernel only goes back to disk if the page gets evicted (system needs the RAM for something else).

---

## Why It Matters for Security

The page cache is **global**. It's shared across:

- All users on the system
- All processes
- All containers on the same host (they share the kernel)
- All namespaces (including user namespaces)

If something corrupts the page cache copy of a file, **every process on the system sees the corrupted version**. The on-disk file stays clean — only the in-memory copy changes. This makes cache corruption attacks invisible to file integrity tools like AIDE, Tripwire, or IMA that check the disk.

---

## How Attackers Abuse It

The general pattern for page-cache exploitation:

1. Get the kernel to load a **setuid root binary** (like `/usr/bin/su`) into the page cache
2. Find a way to **write** into the cached pages — this is the hard part, and each CVE finds a different write primitive
3. Overwrite the binary's code with a small shellcode stub
4. **Run the binary** — the kernel loads it from the corrupted cache, the setuid bit grants root privileges, and the shellcode runs as root

Known vulnerabilities that abuse the page cache:

| CVE | Name | Write Primitive |
|-----|------|----------------|
| CVE-2016-5195 | [[Dirty COW (CVE-2016-5195)\|Dirty COW]] | Race condition in copy-on-write |
| CVE-2022-0847 | Dirty Pipe | Pipe buffer flag manipulation |
| CVE-2026-46300 | [[Fragnesia Page Cache Corruption\|Fragnesia]] | skb fragment flag stripping + ESP in-place decrypt |

---

## Cleanup

Corrupted pages stay in the cache until evicted. To force the kernel to drop all cached pages and reload from disk:

```bash
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
```

A reboot also clears it. Until one of these happens, every execution of the corrupted binary runs the attacker's code.

---

## Related Notes

- [[Fragnesia Page Cache Corruption]]
- [[Dirty COW (CVE-2016-5195)]]
- [[User Namespaces]]
