---
title: "SSH2John"
created: 2026-03-11
type: tool
tags: [tool, cracking, hashing, ssh]
---

# SSH2John

Converts a passphrase-protected SSH private key (`id_rsa`) into a hash format John can crack. If you find a private key but it's encrypted with a passphrase, this is how you recover it.

---

## Workflow

### 1. Convert the key to a crackable hash

```bash
ssh2john id_rsa > ssh_hash.txt
```

If `ssh2john` isn't in your PATH, find it:

```bash
find / -name "ssh2john*" 2>/dev/null
```

Common locations:
- `/usr/share/john/ssh2john.py` (Kali)
- `/opt/john/ssh2john.py` (AttackBox)

Run with Python if needed:

```bash
python3 /usr/share/john/ssh2john.py id_rsa > ssh_hash.txt
```

### 2. Crack the passphrase

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt
```

### 3. Use the key

```bash
chmod 600 id_rsa
ssh -i id_rsa user@target
# Enter the cracked passphrase when prompted
```

---

## Related Notes

- [[John Basics]] — cracking commands
- [[GPG2John]] — same concept for GPG keys
- [[Password Protected Zip & RAR Files]] — same concept for archives
- [[SSH Authentication]] — how SSH keys work
