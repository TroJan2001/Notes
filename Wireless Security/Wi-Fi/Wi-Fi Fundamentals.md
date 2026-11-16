---
title: "Wi-Fi Fundamentals"
created: 2026-11-16
type: concept
tags: [wireless, wifi, concept]
---

Wi-Fi lets devices communicate using radio signals instead of cables, following the IEEE 802.11 standards.

## Key Components

**Access Point (AP):** The device broadcasting the Wi-Fi signal — the bridge between wireless devices and the wired network. A home router is an AP.

**Clients:** Devices connecting to the AP — phones, laptops, tablets, printers. Each has a wireless NIC (Network Interface Card) that handles sending and receiving radio signals.

## Network Identifiers

**SSID (Service Set Identifier):** The human-readable network name you see in your Wi-Fi settings. E.g., `Office_WiFi`.

**BSSID (Basic Service Set Identifier):** The MAC address of the AP's wireless interface. Unique to the hardware. Tools like `airodump-ng` use this to identify specific access points. E.g., `00:1A:2B:3C:4D:5E`.

## Frequency Bands

| | 2.4 GHz | 5 GHz |
|---|---------|-------|
| **Speed** | Up to ~600 Mbps | Up to ~1300 Mbps |
| **Range** | ~45m indoors | ~15m indoors |
| **Wall penetration** | Good | Poor |
| **Congestion** | Crowded (shared with microwaves, Bluetooth, baby monitors) | Much less congested |

2.4 GHz and 5 GHz are both in the **ISM band** (Industrial, Scientific, Medical) — unlicensed frequencies anyone can use for free. That's why Wi-Fi chose them, but it's also why 2.4 GHz is crowded.

## Association Process

When a device joins a Wi-Fi network, it goes through a multi-step handshake:

1. **Scanning** — device listens for nearby networks broadcasting SSIDs
2. **Authentication** — device sends auth request to AP. In most cases the AP just says "sure" (Open System Authentication) — no credential check yet
3. **Association** — device formally registers with the AP, gets assigned resources
4. **Security handshake** — the real credential check:
   - **WPA2-Personal:** 4-way handshake proves the device knows the pre-shared key
   - **WPA2-Enterprise:** device gets sent to a RADIUS server for username/password or certificate auth
5. **Data flows** — only after all steps succeed

Authentication and association are separate steps. The device gets "let in the door" first, then proves who it is. Some attacks target this separation (deauthentication forces reconnection to capture the handshake).

## Factors That Degrade Wi-Fi

- **Physical barriers** — walls, floors, concrete, metal, even water (fish tanks)
- **Distance** — signal weakens with range
- **Interference** — other devices on the same frequency (microwaves, Bluetooth, neighboring Wi-Fi)
- **Channel congestion** — multiple networks on overlapping channels competing for airtime
- **Signal leakage** — signal extends beyond intended boundaries (streets, parking lots, adjacent offices)

## Wi-Fi Generations

| Standard | Name | Frequency | Max Speed | Key Feature |
|----------|------|-----------|-----------|-------------|
| 802.11a | — | 5 GHz | 54 Mbps | First 5 GHz standard |
| 802.11b | — | 2.4 GHz | 11 Mbps | First widely adopted |
| 802.11g | — | 2.4 GHz | 54 Mbps | Backward compatible with b |
| 802.11n | Wi-Fi 4 | 2.4/5 GHz | 600 Mbps | MIMO (multiple antennas) |
| 802.11ac | Wi-Fi 5 | 5 GHz | 1300 Mbps | Wider channels, MU-MIMO |
| 802.11ax | Wi-Fi 6 | 2.4/5 GHz | 9.6 Gbps | OFDMA, better in dense environments |

Most enterprises deploy Wi-Fi 5 and Wi-Fi 6.

## Related Notes

- [[Wi-Fi Security Protocols]] — WEP through WPA3 evolution
- [[Wi-Fi Attacks]] — evil twin, deauth, rogue AP
- [[Wi-Fi Hacking]] — practical aircrack-ng toolchain
