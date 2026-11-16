---
title: "Bluetooth Fundamentals"
created: 2026-11-16
type: concept
tags: [wireless, bluetooth, concept]
---

Bluetooth enables direct wireless communication between devices over short range (typically 10-100m) on the 2.4 GHz band. No router or AP needed — devices talk peer-to-peer.

Common devices: wireless keyboards/mice, headphones, smartwatches, car infotainment, IoT/smart home devices.

## Classic Bluetooth vs BLE

| | Classic Bluetooth | BLE (Bluetooth Low Energy) |
|---|------------------|---------------------------|
| **Purpose** | Continuous streams (audio, file transfer) | Small data bursts (heart rate, sensor readings) |
| **Power** | Higher | Very low |
| **Connection** | Stays connected | Quick send, back to sleep |
| **Analogy** | Phone call | Text message |
| **Devices** | Headphones, speakers, keyboards | Fitness trackers, smart locks, beacons |
| **Security** | Proper pairing with crypto exchange | "Just Works" mode on cheap devices (no verification) |

BLE's "Just Works" pairing mode is common on low-cost IoT devices — no user verification at all, making MITM attacks trivial.

## How Pairing Works

Before two Bluetooth devices communicate, they must pair — establish a secure connection.

### Old Way (pre-2.1): PIN-Based

Both devices agree on a PIN code. One displays it, the other enters it (or both enter the same code). Problem: most people leave it as `0000` or `1234`, and the exchange can be intercepted or brute-forced.

### Modern Classic Bluetooth (2.1+): Secure Simple Pairing (SSP)

Replaced PIN-based pairing with cryptographic key exchange (Elliptic Curve Diffie-Hellman). The devices negotiate keys behind the scenes and show a **6-digit confirmation number** on both screens. You verify they match and hit confirm — you're not typing a password, you're confirming the crypto succeeded.

### Modern BLE (4.2+): LE Secure Connections

Similar cryptographic approach to SSP. Older BLE devices (4.0-4.1) use **LE Legacy Pairing**, which provides weaker protection.

## Security Risks

- **Unnecessary discoverability** — leaving a device in discoverable mode exposes it to nearby attackers
- **Weak pairing** — older devices with simple PINs or "Just Works" mode
- **Lack of updates** — outdated firmware with known vulnerabilities
- **Proximity ≠ safety** — Bluetooth's limited range gives a false sense of security, but conferences, airports, and offices are full of potential attackers within range

## Related Notes

- [[Bluetooth Attacks]] — bluejacking, bluesnarfing, bluebugging
- [[Wi-Fi Fundamentals]] — another 2.4 GHz technology
