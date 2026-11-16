---
title: "Abusing Vulnerable Software"
created: 2026-03-11
updated: 2026-11-16
type: technique
tags: [privesc, technique, windows]
---

Installed software that isn't kept up to date can contain known vulnerabilities with public exploits. Unlike misconfigurations, this is about bugs in the code itself — buffer overflows, race conditions, logic errors — assigned CVE identifiers with published exploit code.

---

## Enumeration

List installed software and versions:

```
wmic product get name,version,vendor
```

`wmic product` won't catch everything — some programs installed outside the standard Windows Installer won't appear. Also check:
- Desktop shortcuts and Start menu entries
- Running services (`sc query state= all`)
- Program Files directories (`dir "C:\Program Files"` and `dir "C:\Program Files (x86)"`)
- Listening ports that might belong to third-party software (`netstat -ano`)

---

## Research

Once you have software names and versions, search for known exploits:

```bash
searchsploit <software> <version>
```

Also check:
- **Google:** `<software> <version> privilege escalation CVE`
- **GitHub:** `CVE-YYYY-XXXXX` repos with PoC code
- **Exploit-DB:** searchable online database
- **Packet Storm:** alternative exploit archive

Automated tools like WinPEAS will flag some known vulnerable versions during their scan.

---

## Methodology

Don't just download and run — follow this workflow:

1. **Enumerate** — identify software, versions, and what runs as a privileged user
2. **Research** — find CVEs and public exploits for those versions
3. **Evaluate** — read the exploit code. Check: does it need compilation? Does it match the target architecture (x86/x64)? Will it crash the system? Does it need specific conditions (e.g., a service restart)?
4. **Exploit** — transfer to target, compile if needed, execute
5. **Verify** — confirm escalation with `whoami`, `id`, and try accessing restricted resources

---

## Example: RPC Services

A common pattern is software that runs an RPC server or local service as SYSTEM on a localhost port. If that service exposes a command execution function (or has a path traversal bypass around input validation), any local user can trigger commands as SYSTEM by connecting to the local port.

The general approach:
1. Find the listening port (`netstat -ano`)
2. Identify the process (`tasklist /FI "PID eq <pid>"`)
3. Research that software version for CVEs
4. Use or adapt the published PoC

---

## Related Notes

- [[Windows Automated Enumeration Tools]] — WinPEAS flags known vulnerable software
- [[Windows Services]] — services running vulnerable binaries
- [[Methodology]] — exploit evaluation fits into Phase 3
