---
title: "IoT Wireless Protocols"
created: 2026-11-16
type: concept
tags: [wireless, iot, concept]
---

Wireless protocols used in smart devices and IoT systems beyond Wi-Fi and Bluetooth.

## Zigbee

Low-power, short-range **mesh protocol** for smart home devices (lights, sensors, smart plugs). Every device relays data to its neighbors, extending the network's range.

**Security risk:** When a new device joins without a pre-configured key, the coordinator may transmit the network encryption key protected only by a well-known default link key. Sniff that pairing moment, and you can decrypt all traffic. A single compromised device in the mesh can relay malicious commands to every other device.

**Mitigation:** Use install codes for device pairing — derives a unique link key per device.

## Z-Wave

Similar to Zigbee — home automation (thermostats, locks, blinds). Uses a more standardized protocol with wider range.

Has two security frameworks:
- **S0** (old) — encrypted the pairing key with **all zeroes**. Interception is trivial.
- **S2** (new) — proper Diffie-Hellman key exchange. But devices supporting both can be forced into a **downgrade from S2 to S0** because the pairing handshake is unauthenticated.

**Mitigation:** Disable S0 backward compatibility on controllers.

## LoRa (Long Range)

Designed for **long-distance, low-power** IoT: environmental monitoring, agricultural sensors, smart streetlights. Sends small amounts of data over several kilometers.

**Security risk:** Devices activated by personalization (ABP) use static session keys. If the frame counter resets, an attacker can replay captured traffic. Devices in remote locations are physically accessible to tampering.

**Mitigation:** Use over-the-air activation (OTAA) which generates fresh session keys per join.

## Cellular (LTE-M, NB-IoT)

IoT devices using the mobile phone network. Smart meters, vehicle trackers, remote sensors. Better security than the others (SIM-based auth, LTE encryption), but devices are often remote, hard to patch, and run minimal software stacks.

**Mitigation:** Change default credentials, place behind VPN/private APN, apply firmware updates.

## Infrared

Uses light signals for line-of-sight communication. TV remotes, AC remotes, projectors. **Zero authentication, zero encryption.** Anyone can capture and replay the signal. Commands follow publicly documented protocols (NEC, RC5) — an attacker can construct valid commands from the spec without capturing anything.

**Mitigation:** Deactivate unused IR receivers on network-connected devices.

## General IoT Principle

Always **segment IoT devices onto dedicated network segments** — isolate them from systems handling sensitive data. A compromised smart bulb shouldn't be a path to the domain controller.

## Related Notes

- [[Wi-Fi Fundamentals]] — the most common IoT transport
- [[Bluetooth Fundamentals]] — another common IoT protocol
- [[RFID & NFC]] — tag-based identification
