---
title: "Fragnesia Page Cache Corruption (CVE-2026-46300)"
created: 2026-11-15
type: technique
tags: [cve, linux, privesc, kernel, technique]
---

# Fragnesia (CVE-2026-46300)

A local privilege escalation in the Linux kernel. CVSS 7.8. Disclosed May 13, 2026 by William Bowling (Zellic), found using the V12 AI-assisted auditing tool.

**Result:** unprivileged user → root in under a second.

---

## Core Concepts

### Socket Buffers (skb)

When the kernel receives a network packet, it wraps it in an **sk_buff (skb)** — an envelope that holds metadata (source, destination, protocol) and **pointers to the actual data in RAM**. The data is stored in **fragments** — each fragment points to a page of RAM.

Normally, fragment pages are **private** to the network stack. Nobody else uses them. Writing to them is safe.

### splice() and Shared Fragments

`splice()` is a zero-copy system call. Instead of copying file data into a new buffer, it makes the skb's fragment point directly at the **[[Page Cache|page cache]]** — the kernel's RAM copy of the file. Now the fragment and the page cache are the **same physical memory**.

The kernel marks these fragments with a flag: **SKBFL_SHARED_FRAG** — a warning that says "this memory is shared, do NOT write to it." Any code that wants to modify the data must copy it to a private page first.

### The Bug: skb_try_coalesce() Strips the Flag

When the kernel merges two skbs for efficiency, `skb_try_coalesce()` moves fragments from one skb to another. It copies the page references but **does not copy the SKBFL_SHARED_FRAG flag**. The flag stays on the old skb (which gets discarded).

After the merge, the fragment still points at the page cache, but now has **no warning flag**. The kernel treats it as private memory.

```
Before merge:
  skb B: [fragment → page cache]  flag: SHARED = true

After merge:
  skb A: [fragment → page cache]  flag: SHARED = ??? (lost!)

  skb A thinks this is private memory. It's not.
```

This bug existed since **2013** (commit cef401de7be8) but was dormant for 13 years.

---

## The Dirty Frag Connection

### The Original Dirty Frag Bug (CVE-2026-43284)

`esp_input()` — the function that decrypts incoming ESP (IPsec) packets — had a fast path that decrypted **in-place** without checking if fragments were shared. If a splice'd page-cache fragment reached it, it would write decrypted data directly into the page cache.

### The Dirty Frag Patch (May 8, 2026)

The fix (commit f4c50a4034e6) did two things:
1. Made splice paths **set** SKBFL_SHARED_FRAG on page-cache fragments
2. Made `esp_input()` **check** the flag — if set, copy first, then decrypt

This fix was correct. But for the **first time ever**, a critical security decision depended on the flag being accurate.

### How the Patch Created Fragnesia (May 13, 2026)

The 2013 flag-stripping bug in `skb_try_coalesce()` was suddenly exploitable:

```
2013–2026:  coalesce strips the flag → nobody checks it → harmless
May 8:      esp_input() now trusts the flag for security
May 13:     Strip flag via coalesce → esp_input() sees no flag →
            decrypts in-place → page cache corrupted → root
```

**A security patch for one vulnerability activated a 13-year-old dormant bug.**

---

## The Exploit Chain

### Step 1: Set Up Capabilities

The attacker creates a **[[User Namespaces|user namespace]]** to get `CAP_NET_ADMIN` (needed to configure IPsec/XFRM). Any unprivileged user can do this.

### Step 2: Prepare the Target

Opens `/usr/bin/su` (a setuid root binary) and uses `splice()` to pipe it into a TCP socket. The skb's fragment now points at the page cache, with the SKBFL_SHARED_FRAG flag set correctly.

### Step 3: Strip the Flag

Network conditions trigger `skb_try_coalesce()`, which merges skbs and **drops the flag** from the page-cache fragment.

### Step 4: Trigger the Write

The attacker sends crafted encrypted data through an **ESP-in-TCP** connection (IPsec encapsulated in TCP). The XFRM subsystem receives it, and `esp_input()` decrypts using **AES-GCM in-place**. Since the flag is gone, it writes directly into the page cache.

The attacker controls the ciphertext, so they control the decrypted output — but only **1 byte per trigger**.

### Step 5: Corrupt the Binary

A 192-byte ELF stub (minimal shellcode that spawns `/bin/sh`) overwrites the beginning of `/usr/bin/su` in the page cache. Takes ~176 triggers (some bytes already match). Completes in **hundreds of milliseconds**.

### Step 6: Get Root

```bash
# Exit the namespace
exit

# Run the corrupted binary from the host
/usr/bin/su
# Kernel loads from corrupted page cache
# setuid bit grants UID 0
# Shellcode executes → root shell
whoami   # root
```

The on-disk `/usr/bin/su` is untouched. Only the page cache copy is corrupted.

---

## The Second Variant: skb_segment()

Two days after disclosure (May 15, 2026), the same researcher found `skb_segment()` — the function that splits large packets for GSO (Generic Segmentation Offload) — has the same flag-stripping bug. It only propagates the flag from the head skb, not from frag_list members.

This variant is harder to trigger (needs 3 network namespaces, depends on GRO timing) but bypasses the coalesce fix. The modprobe denylist blocks both variants.

---

## Detection

The exploit produces a syscall sequence no legitimate application creates.

### Highest-Fidelity Signal

`setsockopt(TCP_ULP, "espintcp")` from a non-IPsec process. Legitimate espintcp use is almost exclusively strongSwan NAT traversal. Anything else is suspicious.

### auditd Rules

```bash
-a always,exit -F arch=b64 -S setsockopt -F a0!=-1 -k fragnesia_setsockopt
-a always,exit -F arch=b64 -S unshare -F a0=0x10000000 -k fragnesia_unshare
-a always,exit -F arch=b64 -S splice -k fragnesia_splice
```

### Falco Rule

```yaml
- rule: Potential Fragnesia exploit (espintcp ULP after splice)
  condition: >
    (evt.type = splice and fd.name in (setuid_binaries)) or
    (evt.type = setsockopt and evt.arg.optname = TCP_ULP and
     proc.name not in (charon, charon-systemd, pluto, swanctl))
  priority: CRITICAL
  tags: [host, exploit, privilege_escalation, cve_2026_46300]
```

### Key Syscalls

| Syscall | What to Watch | Signal Strength |
|---------|--------------|-----------------|
| `unshare(CLONE_NEWUSER \| CLONE_NEWNET)` | Unprivileged process creating both namespaces | High — first step |
| `setsockopt(TCP_ULP, "espintcp")` | Non-strongSwan process | Highest — very low false positive |
| `socket(AF_ALG, SOCK_SEQPACKET)` | Non-crypto process | Medium — also used in Copy Fail |
| `splice()` from setuid binary to TCP socket | Page-cache page entering network | High — trigger preparation |

### Blind Spots

File integrity tools (AIDE, Tripwire, IMA) that check the on-disk file will **never detect this**. The disk copy is clean. Detection must happen at the **syscall layer in real time**.

---

## Mitigation

### Kernel Patch

The fix (commit f84eca581739) is a two-line change: `skb_try_coalesce()` now propagates the SKBFL_SHARED_FRAG flag when transferring fragments.

### Interim: Module Denylist

Block the kernel modules the exploit depends on:

```bash
sudo sh -c 'printf "install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n" > /etc/modprobe.d/dirtyfrag.conf'
sudo rmmod esp4 esp6 rxrpc 2>/dev/null
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
```

**Warning:** This breaks legitimate IPsec (strongSwan, libreswan) and AFS. Safe for most server workloads that don't use these protocols. If you already applied the Dirty Frag modprobe denylist, you're already protected.

### Disable Unprivileged User Namespaces

```bash
sudo sysctl -w kernel.unprivileged_userns_clone=0
```

Blocks the exploit's first step but breaks rootless containers and some browser sandboxing. See [[User Namespaces]].

---

## Bug Class

Fragnesia is not a single bug — it's a **class**. Any kernel function that transfers fragments between skbs and fails to copy SKBFL_SHARED_FRAG is a potential variant. The kernel has many such functions. The discovery rate is accelerating (Dirty Frag bugs took years to find; Fragnesia took 5 days), partly attributed to AI-assisted code auditing.

---

## MITRE ATT&CK

| Technique | ID | Where |
|-----------|-----|-------|
| Exploitation for Privilege Escalation | T1068 | The kernel LPE |
| Abuse Elevation Control: Setuid/Setgid | T1548.001 | execve of corrupted `/usr/bin/su` |
| Escape to Host | T1611 | When run from inside a container |
| Indicator Removal | T1070 | Manual `drop_caches` after exploitation |

---

## Related Notes

- [[Page Cache]]
- [[User Namespaces]]
- [[Dirty COW (CVE-2016-5195)]]
