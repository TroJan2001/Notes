---
title: "Managed Service Accounts"
created: 2026-11-12
type: concept
tags: [concept, active-directory, windows, kerberos]
---

# Managed Service Accounts

Services running on Windows — web servers, databases, scheduled tasks, monitoring agents — need accounts to run under. Using a regular user account is a security problem:

- Passwords expire and someone has to rotate them manually
- People set weak, long-lived passwords that never change
- Multiple services sharing one account means one compromise hits all of them
- Service account passwords end up in scripts, config files, or documentation

Microsoft's answer was **Managed Service Accounts (MSAs)** — accounts whose passwords are managed automatically by Active Directory, removing human error from the equation.

---

## sMSA (Standalone Managed Service Account)

**Introduced:** Windows Server 2008 R2

AD auto-rotates the password (120+ character random string) every 30 days. No human touches the password — the service keeps running seamlessly.

**How it works:** The computer and the KDC (Key Distribution Center on the DC) share a secret. The KDC generates the password, and the local machine retrieves it automatically when it needs to authenticate.

**Limitation:** One sMSA can only be bound to **one machine**. If your service runs on three servers behind a load balancer, you need three separate sMSAs — three separate identities for what's conceptually one service.

---

## gMSA (Group Managed Service Account)

**Introduced:** Windows Server 2012

Solves the multi-server problem. A single gMSA can be used across multiple machines. The **Key Distribution Service (KDS)** on the DC generates the password, and any authorized machine can retrieve it.

**How it works:** The KDS uses a root key plus a time-based derivation algorithm to generate the password deterministically. Any computer listed in the gMSA's `PrincipalsAllowedToRetrieveManagedPassword` attribute can compute the current password on its own. Password rotates every 30 days by default.

**Limitation:** Every machine that uses the gMSA must be explicitly added to the allowed list. In large environments with hundreds of services across dozens of servers, managing this becomes complex — especially during deployments and decommissions.

---

## dMSA (Delegated Managed Service Account)

**Introduced:** Windows Server 2025

The newest type. Designed to make **migrating from legacy service accounts** to managed ones easier. The old sMSA/gMSA approach requires reconfiguring every application that uses the old account. dMSA avoids this with a feature called **succession**.

### How Succession Works

A dMSA can "take over" from an existing account by inheriting its Kerberos keys:

1. Create a dMSA object in an OU
2. Set its `msDS-ManagedAccountPrecededByLink` attribute to point to the old account
3. Set `msDS-DelegatedMSAState` to indicate succession status (2 = complete)
4. The DC sees the succession link and gives the dMSA the old account's Kerberos keys when it authenticates

Applications configured to use the old account don't need to change — the dMSA presents the same Kerberos identity.

### Succession Does NOT Delete the Original

This is a common misconception. Succession is like **duplicating a key**, not transferring it. The original account still exists, still has its password, still works. Both accounts function simultaneously. The dMSA just gets a copy of the Kerberos keys.

### The Security Flaw

The succession mechanism performs **no authorization check**. Anyone who can create a dMSA in an OU (just CreateChild permission) can set it to succeed **any account in the domain**, including Administrator. The DC doesn't verify the creator's right to access the target account. This is the [[BadSuccessor Attack]].

---

## The `$` Suffix Convention

In AD, **machine accounts and managed service accounts** end with `$`:

| Account | Type |
|---------|------|
| `DC01$` | Computer account |
| `SQL_gMSA$` | Group managed service account |
| `pentest_dmsa$` | Delegated managed service account |
| `WORKSTATION01$` | Domain-joined workstation |

The `$` tells you it's not a regular user account. This matters for tools — Impacket, Rubeus, and other Kerberos tools need the `$` to authenticate correctly as these account types. Regular user accounts (`tbyte`, `Administrator`) never have the suffix.

---

## Related Notes

- [[BadSuccessor Attack]]
- [[Organizational Units and DACLs]]
- [[Kerberos Authentication Flow]]
- [[Credential Extraction & Abuse]]
