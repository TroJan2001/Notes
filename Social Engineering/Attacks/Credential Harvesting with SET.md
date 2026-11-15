---
title: "Credential Harvesting with SET"
created: 2026-11-15
type: technique
tags: [social-engineering, phishing, tool, technique]
---

# Credential Harvesting with SET

The **Social Engineering Toolkit (SET)** can clone a login page and host it locally. When a target submits credentials on the fake page, SET captures them and displays them in the terminal.

---

## Setup Steps

### 1. Launch SET

```bash
sudo setoolkit
```

### 2. Navigate the Menus

```
1) Social-Engineering Attacks
  → 2) Website Attack Vectors
    → 3) Credential Harvester Attack Method
      → 3) Custom Import     (or 2 for Site Cloner in real engagements)
```

### 3. Configure the Harvester

- **IP for POST back:** your attacker IP (where credentials get sent)
- **Path to website:** folder containing your `index.html` (e.g., `/home/attacker/setoolkit/`)
- **Copy option:** `1` (Copy just the index.html)
- **URL of imported site:** the typosquatted domain (e.g., `http://tryacounting.thm`)

SET starts listening on port 80. Leave the terminal open.

### 4. Send the Phishing Email

Use a mail client, GoPhish, or SET's own Mass Mailer to send an email containing the fake URL to the target. Key techniques:

- **From address:** use an alias or spoofed address that looks internal (e.g., `support@company.thm`)
- **Subject:** something urgent — "Password Expiration Notice", "Account Verification Required"
- **Body:** reference a real policy, include the fake URL, apply [[Social Engineering Principles|urgency/authority]]
- **Domain:** use a typosquatted domain for the link (e.g., one letter missing)

### 5. Capture Credentials

When the target submits the form, SET displays:

```
[*] WE GOT A HIT! Printing the output:
POSSIBLE USERNAME FIELD FOUND: username=bob.wilkinson
POSSIBLE PASSWORD FIELD FOUND: password=S3cur3P@ss!
```

The target sees a failed login and gets redirected to the real site. They try again, it works, and they think nothing happened.

---

## Harvester Modes

| Mode | Use Case |
|------|----------|
| **Web Templates** | Pre-built clones of common sites (Google, Facebook, etc.) |
| **Site Cloner** | Clones any URL automatically — best for real engagements |
| **Custom Import** | Use your own HTML — full control over the fake page |

---

## Tips for Real Engagements

- **Site Cloner** is usually better than Custom Import — it replicates the real page perfectly
- Host the harvester on a typosquatted domain with a valid TLS certificate for credibility
- Keep sessions short — the captured credentials might rotate or get invalidated
- Combine with email spoofing (display name + lookalike domain) for maximum effectiveness
- Always have legal authorization before running credential harvesting

---

## Related Notes

- [[Phishing Attacks]]
- [[Social Engineering Principles]]
- [[Authentication Bypass]]
