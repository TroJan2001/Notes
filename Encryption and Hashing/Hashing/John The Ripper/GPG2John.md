---
title: "GPG2John"
created: 2026-03-11
type: tool
tags: [cracking, crypto, hashing, linux, tool]
---

# Useful Commands

To crack a an asc file so you can access a pgp file, we use the following commands:

```bash
gpg2john name.asc > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
gpg --import name.asc
gpg --decrypt somecredentials.pgp # Enter the password you have found
```