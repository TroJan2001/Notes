---
title: "TLS and SSL"
created: 2026-11-09
type: concept
tags: [concept, crypto, encryption, network]
---

## What Is TLS

Transport Layer Security — encrypts communication between client and server. Successor to SSL (which is deprecated and insecure). When someone says "SSL" today, they usually mean TLS.

**Purpose:** Confidentiality (encryption), Integrity (tamper detection), Authentication (certificates prove identity).

## Why It Matters

Without TLS, protocols like HTTP, FTP, SMTP, POP3, and IMAP send everything in **cleartext** — including credentials. Anyone on the network path (man-in-the-middle) can sniff the traffic.

| Cleartext Protocol | Encrypted Version | Port Change |
|-------------------|-------------------|-------------|
| HTTP (80) | HTTPS (443) | Yes |
| FTP (21) | FTPS (990) | Yes |
| SMTP (25) | SMTPS (465) | Yes |
| POP3 (110) | POP3S (995) | Yes |
| IMAP (143) | IMAPS (993) | Yes |

## TLS Handshake (Simplified)

1. **Client Hello** — client sends supported TLS versions and cipher suites
2. **Server Hello** — server picks TLS version and cipher suite, sends its certificate
3. **Certificate Verification** — client checks the certificate against trusted CAs
4. **Key Exchange** — both sides agree on a shared session key (using asymmetric crypto like Diffie-Hellman)
5. **Encrypted Communication** — all data encrypted with the shared symmetric key

After the handshake, symmetric encryption is used (faster than asymmetric) for the actual data transfer.

## Certificates

- Issued by **Certificate Authorities (CAs)** — trusted third parties
- Contain: domain name, public key, issuer, expiration date
- Browser checks: is the CA trusted? Is the domain correct? Is it expired?
- **Self-signed certificates** — not trusted by browsers (no CA verification), common in labs/internal systems

## Pentest Relevance

- **Expired/self-signed certs** — finding, indicates poor security hygiene
- **Mixed content** — HTTPS page loading HTTP resources leaks data
- **SSL stripping** — downgrade HTTPS to HTTP (tools: sslstrip)
- **Weak cipher suites** — outdated algorithms (SSLv3, RC4, DES) can be cracked
- **Certificate transparency logs** — public records of issued certs, useful for subdomain enumeration

## Related

- [[Common Protocols Ports]]
- [[SSH Authentication]]
- [[DH - Asymmetric Encryption]]
- [[PKI]]
