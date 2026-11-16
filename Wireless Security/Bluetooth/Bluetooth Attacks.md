---
title: "Bluetooth Attacks"
created: 2026-11-16
type: technique
tags: [wireless, bluetooth, technique]
---

Bluetooth attacks require the attacker to be within range of the target device (typically 10-100m). Common locations: offices, conferences, airports.

## The Three "Blue" Attacks

Listed in escalating severity:

### Bluejacking — Spam

Sending unsolicited messages to a Bluetooth-enabled device. The attacker abuses the Bluetooth name/contact sharing feature to push messages to nearby devices.

**Impact:** Annoying but mostly harmless. Like someone AirDropping memes on the train.

### Bluesnarfing — Steal

Exploiting a Bluetooth vulnerability to **access and steal data** (contacts, messages, emails, calendar) from a device without the owner knowing.

**Impact:** Data theft. The victim has no indication it's happening.

### Bluebugging — Control

Exploiting a Bluetooth vulnerability to **take control of device functions**. The attacker can make calls, send texts, eavesdrop on conversations — basically remote-control the phone.

**Impact:** Full device compromise. The worst of the three.

## Security Considerations

| Measure | Classic | BLE |
|---------|---------|-----|
| Disable Bluetooth when not in use | Both | Both |
| Turn off discoverable mode | Both | Both |
| Reject unknown pairing requests | Classic | — |
| Use devices supporting SSP (2.1+) or LE Secure Connections (4.2+) | Classic | BLE |
| Keep firmware updated | Both | Both |
| Avoid "Just Works" pairing for sensitive devices | — | BLE |

## Related Notes

- [[Bluetooth Fundamentals]] — Classic vs BLE, pairing process
