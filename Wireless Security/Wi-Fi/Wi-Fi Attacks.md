---
title: "Wi-Fi Attacks"
created: 2026-11-16
type: technique
tags: [wireless, wifi, technique]
---

Common attack concepts targeting Wi-Fi networks. For the practical commands (aircrack-ng toolchain), see [[Wi-Fi Hacking]].

## Deauthentication Attack

Forged "disconnect" frames that kick a client off the network. The attacker sends deauth packets pretending to be the AP, and the client's device obeys because management frames in Wi-Fi are unauthenticated.

**Why it matters:** Forcing a disconnect makes the client reconnect, and during reconnection the 4-way handshake is transmitted. The attacker captures it and cracks it offline.

```bash
sudo aireplay-ng --deauth 0 -a <BSSID> wlan0
```

## Evil Twin Attack

A fake AP with the **same SSID** as a legitimate network. Victims' devices auto-connect to it (especially if the signal is stronger). All their traffic flows through the attacker.

Unlike a rogue AP, an evil twin is **not plugged into the target network** — it operates independently. The goal is intercepting traffic or capturing credentials (e.g., presenting a fake captive portal).

## Rogue Access Point

An **unauthorized AP physically connected** to the target network. Could be set up intentionally by an attacker or accidentally by an employee plugging in a personal router. It provides a wireless entry point into the wired network, bypassing perimeter security.

## Password Attacks

Brute-forcing or dictionary attacks against captured WPA/WPA2 handshakes. The attacker:

1. Captures the 4-way handshake (usually with deauth + airodump-ng)
2. Runs a wordlist against it offline (aircrack-ng, hashcat)

WPA3's SAE makes this impractical since each guess requires live interaction with the AP.

## WPS Attack

Wi-Fi Protected Setup uses an 8-digit PIN for easy connection. The PIN is verified in two halves (first 4 digits, then last 4), reducing the keyspace from 100 million to ~11,000 combinations.

```bash
reaver -i wlan0mon -b <BSSID> -vv
```

## Traffic Interception

If encryption is weak (WEP) or improperly configured, an attacker can capture and read wireless traffic directly. Even with proper encryption, traffic is visible — the attacker just can't decrypt it without the key.

## Protections

- Use WPA2/WPA3 with strong passphrases
- Disable WEP and WPA (legacy protocols)
- Disable WPS if not needed
- Change default admin credentials on APs
- Segment guest networks from internal resources
- Keep AP firmware updated
- Monitor for rogue APs

## Related Notes

- [[Wi-Fi Security Protocols]] — WEP through WPA3 encryption
- [[Wi-Fi Fundamentals]] — how Wi-Fi networks work
- [[Wi-Fi Hacking]] — practical aircrack-ng commands
