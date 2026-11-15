---
title: "Password Protected Zip & RAR Files"
created: 2026-03-11
type: technique
tags: [technique, cracking, hashing]
---

# Password Protected Zip & RAR Files

John's `zip2john` and `rar2john` tools convert password-protected archives into crackable hash format. Same workflow as [[SSH2John]] and [[GPG2John]] — convert first, crack second.

---

## Zip Files

### 1. Extract the hash

```bash
zip2john protected.zip > zip_hash.txt
```

### 2. Crack it

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
```

### 3. Extract the archive

```bash
unzip protected.zip
# Enter the cracked password
```

---

## RAR Files

### 1. Extract the hash

```bash
rar2john protected.rar > rar_hash.txt
```

### 2. Crack it

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt
```

### 3. Extract the archive

```bash
unrar x protected.rar
# Enter the cracked password
```

---

## Other Archive Types

The same pattern works for other formats:

| Tool | Archive Type |
|------|-------------|
| `zip2john` | ZIP |
| `rar2john` | RAR |
| `7z2john` | 7-Zip |
| `keepass2john` | KeePass databases |
| `bitlocker2john` | BitLocker volumes |

---

## Related Notes

- [[John Basics]] — cracking commands
- [[SSH2John]] / [[GPG2John]] — same workflow for keys
