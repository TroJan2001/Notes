---
title: "RFID & NFC"
created: 2026-11-16
type: concept
tags: [wireless, rfid, nfc, concept]
---

RFID and NFC are short-range wireless technologies used for identification, access control, and contactless transactions. NFC is a specific subset of RFID.

## RFID (Radio-Frequency Identification)

Uses electromagnetic fields to identify and track tags. A system has two components:

**Reader (Interrogator):** Emits radio waves. When a tag enters its field, the tag responds with stored data.

**Tags:**
- **Passive** — no battery. Harvests energy from the reader's electromagnetic field (like wireless charging). Cheap, lasts forever, limited range. Used in: office badges, library books, warehouse inventory.
- **Active** — has its own battery. Can transmit over 100m+. More expensive, battery dies eventually. Used for: shipping containers, vehicle tracking.

**How passive tags work:** The reader's radio waves hit the tag's antenna coil, inducing a small electrical current (electromagnetic induction). That current powers the microchip for a fraction of a second — long enough to modulate the field with its stored data. The reader detects those changes.

**Frequency ranges:** 125 KHz to 960 MHz depending on the tag type.

## NFC (Near-Field Communication)

A specific type of RFID that operates at **13.56 MHz** with a range of **~5 cm**.

The key difference from RFID: NFC supports **two-way communication**. Both devices can send and receive — that's why it works for contactless payments (phone and terminal actively negotiate the transaction).

Used in: contactless payments, transit cards, device pairing (tap to pair), hotel key cards.

## Attacks

### Eavesdropping
Intercepting the signal between a card and reader as someone scans their badge.

### Cloning
Copying data from one card to a blank card. Tools like the **Proxmark3** can clone unencrypted badges in seconds. The attacker gets a working copy that opens the same doors.

### Skimming (Unauthorized Scanning)
Secretly reading a card without the owner knowing — attacker walks past with a concealed reader.

### Relay Attack
The clever one. Two attackers, two relay devices:
1. Attacker A stands near the victim (picks up the card's NFC signal from their pocket)
2. Attacker B stands at a payment terminal in a shop
3. The two devices relay the communication in real-time over the internet
4. The terminal thinks the card is physically present and processes the payment

This extends the 5cm NFC range across any distance.

## Protections

- Use cards that support encryption
- Limit sensitive data stored on cards (use tokenisation)
- Immediately deactivate lost or stolen cards
- Use **Faraday pouches/sleeves** to block unauthorized scanning
- Implement secondary biometric authentication where possible
- Update access controls regularly

## Related Notes

- [[Bluetooth Fundamentals]] — another short-range wireless technology
- [[Wi-Fi Fundamentals]] — wireless networking
