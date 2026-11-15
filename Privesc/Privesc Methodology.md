---
title: "Privesc Methodology"
created: 2026-11-16
updated: 2026-11-16
type: methodology
tags: [methodology, privesc, enumeration]
---

# Privesc Methodology

A structured approach to privilege escalation on any host. Check every category, chain findings across them, and exploit the most direct path first.

---

## Two Types of Privilege Escalation

| | Vulnerability-Based | Configuration-Based |
|--|-------------------|-------------------|
| **Exploits** | Bugs in software — kernel CVEs, buffer overflows, unpatched services | Mistakes in how the system is set up |
| **Patching** | Removes the vector | Doesn't help — the system is patched but misconfigured |
| **Reliability** | Depends on specific version + conditions | Works on fully patched systems |
| **Frequency** | Less common in mature environments | Most common vector in practice |

Configuration-based escalation is the primary focus. A fully patched host with poor hardening is often easier to escalate than an unpatched host with tight configuration.

---

## Phase 1 — Situational Awareness

Before looking for misconfigurations, understand the host:

| Question | Why It Matters |
|----------|---------------|
| Who am I? (`whoami`, `id`, group memberships) | Already admin? Different paths for different privilege levels |
| What OS and version? | Determines which techniques and tools apply |
| What's the hostname and role? | Web server vs domain controller vs workstation = different opportunities |
| Domain-joined? | Opens AD-based escalation paths on Windows |

This shapes everything that follows. Don't enumerate blindly.

---

## Phase 2 — Category-Based Enumeration

Walk through all six categories every time. Consistent order prevents skipping one under time pressure.

### 1. Users and Groups

Look for accounts with more privilege than they need.

- Users in admin/sudo/root groups unnecessarily
- Service accounts with excessive privileges
- Default accounts left enabled (guest, administrator with default password)
- Weak or absent password policies

### 2. File and Directory Permissions

Who can read, write, or execute what they shouldn't.

**Linux:**
- **SUID binaries** — runs as the file owner (usually root) regardless of who executes it. If the binary allows command execution or file access, it's a direct escalation vector
- SGID binaries — runs with the file's group privileges
- World-writable files/directories, especially those executed by root
- Sensitive files readable by everyone (`/etc/shadow`, SSH private keys)

**Windows:**
- Weak ACLs on directories in the system PATH
- Writable program installation directories
- Misconfigured registry key permissions

### 3. Services

Background processes and their privilege levels.

- Services running as root/SYSTEM unnecessarily
- Service binaries or config files writable by low-privilege users
- **Unquoted service paths** (Windows) — `C:\Program Files\My App\service.exe` without quotes makes Windows try `C:\Program.exe`, then `C:\Program Files\My.exe` first. Drop a malicious binary at an intermediate path → runs as the service account

### 4. Scheduled Tasks / Cron Jobs

Automated commands that run on a schedule.

- Privileged cron job referencing a script you can modify → edit the script, wait for execution
- **Wildcard injection** — a root cron running `tar cf /backup/archive.tar *` in a writable directory. Create files named `--checkpoint=1` and `--checkpoint-action=exec=sh shell.sh`. Tar interprets the filenames as arguments and executes your script as root
- Task Scheduler entries on Windows with weak permissions on referenced binaries

### 5. Credential Storage

Passwords left where they shouldn't be.

**Linux:** `.bash_history`, environment variables, config files (DB connection strings, API keys), readable SSH private keys

**Windows:** `cmdkey /list` (saved creds), `runas /savecred`, registry passwords, `Unattend.xml` / Sysprep files, PowerShell history, `web.config`

Often the most direct path — no technical exploit needed, just a password sitting in a file.

### 6. Network Configuration

Less about local privesc, more about expanding attack surface.

- Services bound to `0.0.0.0` instead of `127.0.0.1`
- Unnecessary open ports
- Permissive firewall rules exposing management interfaces
- Database services reachable from the network with weak auth

---

## Phase 3 — Prioritise and Exploit

Enumeration usually produces multiple findings. Rank by directness:

| Priority | Example | Why |
|----------|---------|-----|
| Highest | Stored root/admin password | Immediate escalation, no waiting |
| High | Writable SUID binary owned by root | Direct code execution as root |
| Medium | Writable script in a root cron job | Works but need to wait for next execution |
| Lower | Weak service ACL | Requires service restart or additional steps |

### Chaining Findings Across Categories

Individual low-severity findings combine into high-severity attack paths. This is the core skill.

Example chain:
```
Root cron job runs /opt/scripts/backup.sh every 5 min  (scheduled task finding)
  + backup.sh is world-writable                        (file permission finding)
  = modify script → wait 5 min → root shell            (escalation)
```

Neither finding alone is critical. The cron job isn't inherently insecure. A world-writable file never executed by root is low priority. Together, they're a direct privesc path.

---

## Tools

### Offensive Enumeration

| Tool | Target OS | Purpose |
|------|----------|---------|
| **LinPEAS** | Linux | Automated enumeration across all categories |
| **WinPEAS** | Windows | Same for Windows |
| **PowerUp** | Windows (PowerShell) | Service misconfigurations, unquoted paths |

These automate Phase 2 but don't replace understanding what they check. You interpret the output, spot false positives, and fill gaps manually.

### Defensive / Compliance

| Tool | Type | Notes |
|------|------|-------|
| **Nessus** | Commercial (Tenable) | Vulnerability + compliance scanning against CIS/STIGs |
| **Lynis** | Open-source | Linux hardening audit, can run post-compromise |
| **OpenSCAP** | Open-source | SCAP-formatted profiles, government/enterprise |
| **CIS-CAT** | CIS's own tool | Direct CIS Benchmark evaluation |

If compliance scan output is available (grey/white-box engagement), it's a pre-built list of misconfigurations to investigate.

---

## Security Baselines

Two industry frameworks define what "secure" looks like:

**CIS Benchmarks** — consensus-driven, Level 1 (broadly applicable) and Level 2 (deeper hardening). Hundreds of checks per OS.

**DISA STIGs** — U.S. DoD mandatory standards. Severity: CAT I (highest risk) → CAT II → CAT III. More prescriptive than CIS.

What defenders use to harden is exactly what you use to enumerate. The same checklist works both ways.

---

## Related Notes

- [[Privilege Escalation]] — Linux privesc overview
- [[Basic Enumeration]] — Linux enumeration commands
- [[SUID&GUID Files]] — finding and exploiting SUID binaries
- [[Exploiting Crontab]] — cron job exploitation
- [[Windows Services]] — Windows service misconfigurations
- [[Passwords Usual Spots]] — Windows credential locations
