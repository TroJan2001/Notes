# 🧾 What is LDAP?

**LDAP = Lightweight Directory Access Protocol**

It’s a protocol for **reading and writing directory data** — like usernames, groups, OUs, group policies, etc.

Active Directory (AD) is Microsoft's implementation of a **directory service**, and it speaks LDAP.

---

## ✅ Where is LDAP Used?

- Logging in to domain
    
- Resolving usernames / SIDs
    
- Looking up group membership
    
- GPO application
    
- Service discovery (SPNs, DCs)
    
- Tools like:
    
    - `ldapsearch`, `ADExplorer`, `BloodHound`
        
    - `net user`, `whoami /groups` (under the hood)
        
    - Custom apps using AD for user auth
        

---

# 🔌 Protocol Basics

| Variant                   | Port        | Secure?  | Notes                            |
| ------------------------- | ----------- | -------- | -------------------------------- |
| **LDAP**                  | 389         | ❌ No     | Often upgraded to TLS (STARTTLS) |
| **LDAPS**                 | 636         | ✅ Yes    | LDAP over SSL/TLS                |
| **Global Catalog (LDAP)** | 3268 / 3269 | Optional | Used for cross-domain lookups    |

---

# 🔐 Authentication Over LDAP

LDAP supports multiple **auth methods**:

|Type|Used By|Notes|
|---|---|---|
|**Simple Bind**|Scripts, legacy apps|Sends username & password (cleartext if not over TLS)|
|**NTLM Bind**|Windows|Uses NTLM negotiation inside LDAP|
|**Kerberos Bind**|Windows|Uses SASL with Kerberos|
|**Anonymous**|Rare|Only if server allows it|

---

## ⚠️ Attacks Involving LDAP

### 1. 🕵️ Anonymous or Weak Bind

- Misconfigured servers may allow anonymous access.
    
- Can be abused to enumerate users, groups, SPNs.
    

### 2. 🔁 NTLM Relay to LDAP

- Classic use of `ntlmrelayx`:
    
    - Victim authenticates (NTLM)
        
    - Attacker relays to LDAP
        
    - Attacker sends malicious LDAP operations (add user to group, dump users)
        

### 3. 🧨 LDAP Injection

- Custom web apps using LDAP backends may be vulnerable to injection:
    

`(&(user=*)(password=*))  → could be tricked into bypassing auth`

### 4. 🎣 Credential Harvesting via Misused LDAP Tools

- Fake LDAP server tricks clients into authenticating
    
- Attacker captures hashes (NTLM) or Kerberos tickets
    

---

# 🔍 Common LDAP Queries

```bash
# With ldapsearch (Linux):
ldapsearch -x -H ldap://dc01.domain.local -b "dc=domain,dc=local" "(objectClass=person)"

# With PowerShell:
Get-ADUser -Filter * -Properties *
```

Query Filters use a functional syntax:

`(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=local))`

---

# 🧰 Real Examples

- Dump all users:
    
    `(&(objectClass=user)(sAMAccountName=*))`
    
- Find all domain admins:
    
    `(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,...))`
    
- Find SPNs (for kerberoasting):
    
    `(&(objectClass=user)(servicePrincipalName=*))`
    

---

# 🔐 Defense Tips

- Force LDAPS (disable plain LDAP if possible)
    
- Enforce LDAP signing (`Domain Controller: LDAP Server Signing Requirements`)
    
- Use **Kerberos authentication** over LDAP
    
- Disable anonymous binds
    
- Monitor for unusual LDAP queries (e.g., bulk enumeration)