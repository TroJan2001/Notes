---
title: "GPG2John"
created: 2026-03-11
type: tool
tags: [tool, cracking, hashing, crypto]
---

# GPG2John

Converts a passphrase-protected GPG/PGP key into a hash format John can crack. Used when you find encrypted `.pgp` files and a `.asc` key that's locked with a passphrase.

---

## File Types

| Extension | What It Is |
|-----------|-----------|
| `.asc` | ASCII-armored GPG key (public or private) — text format |
| `.gpg` / `.pgp` | Binary encrypted file or keyring |
| `.key` | Sometimes used for private keys |

---

## Workflow

### 1. Convert the key to a crackable hash

```bash
gpg2john private_key.asc > gpg_hash.txt
```

### 2. Crack the passphrase

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt gpg_hash.txt
```

### 3. Import the key and decrypt

```bash
gpg --import private_key.asc
# Enter the cracked passphrase

gpg --decrypt secret_file.pgp
# Enter the passphrase again to decrypt
```

---

## Related Notes

- [[John Basics]] — cracking commands
- [[SSH2John]] — same concept for SSH keys
- [[Password Protected Zip & RAR Files]] — same concept for archives
- [[GPG]] — how GPG encryption works
