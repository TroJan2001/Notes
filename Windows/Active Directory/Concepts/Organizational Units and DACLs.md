---
title: "Organizational Units & DACLs"
created: 2026-11-12
type: concept
tags: [concept, active-directory, windows]
---

# Organizational Units & DACLs

## Organizational Units (OUs)

OUs are **folders inside Active Directory** for organizing objects — users, computers, groups, printers, and other OUs. They serve two purposes:

### 1. Organization

Group objects logically by department, location, role, or function:

```
DC=company,DC=local
├── OU=IT
│   ├── OU=Servers
│   └── OU=Helpdesk
├── OU=HR
├── OU=Finance
└── OU=Development
```

### 2. Delegation

Grant someone admin rights over just one OU, not the entire domain. For example, an IT helpdesk team might have permission to reset passwords and create user accounts in `OU=Helpdesk`, without having any access to `OU=Finance`.

This delegation is controlled by **DACLs** — the permission lists attached to every AD object.

### OUs vs Groups vs Containers

These are different things that beginners often confuse:

- **OU** — a folder for organizing objects AND applying policies/permissions. You can apply Group Policy to an OU.
- **Security Group** — a list of members. Used to grant access to resources (file shares, applications). You CANNOT apply Group Policy to a group.
- **Container** — a default AD folder like `CN=Users` or `CN=Computers`. Unlike OUs, you cannot apply Group Policy to containers, and you can't create sub-containers. They exist because AD creates them by default.

---

## DACLs (Discretionary Access Control Lists)

Every AD object — every user, computer, group, OU, GPO — has a **DACL** attached to it. The DACL is a list of **ACEs (Access Control Entries)**, where each ACE says:

> "This principal has this permission on this object."

Example ACEs on `OU=LabOU`:

| Principal | Permission | Meaning |
|-----------|-----------|---------|
| `tbyte` | CreateChild | Can create new objects inside this OU |
| `Domain Admins` | GenericAll | Full control over the OU and everything in it |
| `Helpdesk` group | ResetPassword | Can reset passwords of user objects inside this OU |

### Key Permission Types

| Permission | What It Grants | Why It's Dangerous |
|-----------|---------------|-------------------|
| **CreateChild** | Create new objects inside the OU | Can create dMSA objects leading to [[BadSuccessor Attack]] |
| **GenericAll** | Full control — read, write, delete, create children, modify DACL | Complete ownership of the object |
| **WriteDACL** | Modify the permission list itself | Self-escalating — can grant yourself any other permission |
| **WriteOwner** | Change who owns the object | Owners implicitly have full control |
| **WriteProperty** | Modify specific attributes on the object | Impact depends on which attributes — some are harmless, others devastating |
| **Self** | Add/remove yourself from a group | Can add yourself to Domain Admins if the group's DACL allows it |

### Permission Inheritance

ACEs **inherit down the OU tree** unless explicitly blocked. An ACE on a parent OU flows to all child OUs and the objects inside them. This is how delegation works at scale — set permissions once on a top-level OU and they apply to everything underneath.

But it also means a single misconfigured ACE at a high-level OU can expose a large attack surface.

### The Delegation Problem

Permissions like CreateChild seem harmless — "you can create objects, so what?" But:

1. Different object **types** have wildly different security implications. Creating a user is relatively safe. Creating a `msDS-DelegatedManagedServiceAccount` (dMSA) can lead to full domain compromise — see [[BadSuccessor Attack]]
2. **WriteDACL is self-escalating** — once you can change the permissions, you can give yourself any other permission, then remove your tracks
3. The object types you can create aren't always obvious from the permission name. CreateChild on an OU covers ALL child object types unless restricted to specific ones

---

## Enumerating DACLs

### From Windows (PowerShell)

```powershell
# Read the ACL on a specific OU
(Get-Acl "AD:\OU=LabOU,DC=domain,DC=local").Access |
    Where-Object { $_.ActiveDirectoryRights -match 'CreateChild|GenericAll|WriteDacl|WriteOwner' }

# Dedicated scripts exist for finding BadSuccessor-exploitable permissions
# e.g., Get-BadSuccessorOUPermissions.ps1
```

### From Linux

**LDAP signing** is a common obstacle. Modern DCs (especially Server 2025) enforce LDAP signing — all LDAP requests must be cryptographically signed. Raw `ldapsearch` and some Impacket tools (like `impacket-dacledit`) fail with `strongerAuthRequired`. Tools like **nxc** and **bloodyAD** handle signing automatically.

**bloodyAD:**
```bash
# Find all objects you can write to or create children in
bloodyAD -d domain.local -u USER -p PASS --host DC-FQDN get writable --detail
```

Look for `dSA: CREATE_CHILD` on an OU — that means you can create dMSA objects in that OU.

**nxc (NetExec):**
```bash
# Read DACLs on a specific OU
nxc ldap DC_IP -u USER -p PASS -d domain.local \
    -M daclread -o TARGET_DN="OU=SomeOU,DC=domain,DC=local" ACTION=read
```

See [[Enumeration & Reconnaissance]] for more AD enumeration tools.

---

## Related Notes

- [[BadSuccessor Attack]]
- [[Managed Service Accounts]]
- [[Windows AD Privilege Escalation]]
- [[LDAP]]
- [[Enumeration & Reconnaissance]]
