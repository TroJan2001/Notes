---
title: "Wi-Fi Security Protocols"
created: 2026-11-16
type: concept
tags: [wireless, wifi, encryption, concept]
---

Wi-Fi security protocols control who can connect (authentication) and protect data in transit (encryption). They've evolved through four generations, each fixing the previous one's flaws.

## WEP (Wired Equivalent Privacy) — 1999

The original Wi-Fi security protocol. **Broken beyond repair.**

- Uses RC4 stream cipher with static encryption keys
- The key never changes — every packet uses the same key
- The Initialization Vector (IV) is only 24 bits, so it repeats quickly
- An attacker capturing enough packets can recover the key in **minutes**
- Tools: `aircrack-ng` can crack WEP with a few thousand captured packets

Never use WEP. If you see it on a pentest, it's an instant finding.

## WPA (Wi-Fi Protected Access) — 2003

An emergency fix for WEP, designed to work on existing WEP hardware.

- Still uses RC4 but adds **TKIP** (Temporal Key Integrity Protocol)
- TKIP generates a new key for every packet instead of reusing one
- Better than WEP but still built on a weak foundation
- Superseded by WPA2 — considered legacy

## WPA2 (Wi-Fi Protected Access 2) — 2004

The standard for most networks today.

- Replaced RC4/TKIP with **AES encryption** and **CCMP** protocol — much stronger
- Two modes:
  - **Personal (PSK):** Pre-shared key — everyone uses the same password. The 4-way handshake verifies the device knows the key.
  - **Enterprise (802.1X):** Each user authenticates individually via a **RADIUS** server with their own credentials or certificate.

**Weakness:** Vulnerable to **offline dictionary attacks**. If an attacker captures the 4-way handshake (by forcing a reconnection with a deauth attack), they can brute-force the password at their own pace, completely offline. The defense is using a strong, long passphrase.

## WPA3 (Wi-Fi Protected Access 3) — 2018

The newest standard. The big improvement is **SAE (Simultaneous Authentication of Equals)**.

- SAE replaces the 4-way handshake with a zero-knowledge proof
- Even if an attacker captures the authentication exchange, they **cannot brute-force it offline**
- Each password guess requires real-time interaction with the AP, making dictionary attacks impractical
- Also adds **forward secrecy** — compromising today's key doesn't decrypt past traffic
- Enterprise mode adds 192-bit encryption

## Comparison

| | WEP | WPA | WPA2 | WPA3 |
|---|-----|-----|------|------|
| **Encryption** | RC4 (static key) | RC4 + TKIP | AES + CCMP | AES + CCMP/GCMP |
| **Key exchange** | Static | Per-packet | 4-way handshake | SAE |
| **Offline cracking** | Minutes | Possible | Possible (capture handshake) | Resistant |
| **Status** | Broken | Legacy | Current standard | Newest |

## Common Misconfigurations

- Using WEP or WPA instead of WPA2/WPA3
- Weak passwords (short, dictionary words)
- WPS enabled — the 8-digit PIN is checked in two halves (4+4), reducing combinations from 100M to ~11K. Tools like `reaver` crack it in hours
- Default admin credentials on the AP management interface

## Related Notes

- [[Wi-Fi Fundamentals]] — how Wi-Fi works
- [[Wi-Fi Attacks]] — attack concepts
- [[Wi-Fi Hacking]] — practical cracking commands
