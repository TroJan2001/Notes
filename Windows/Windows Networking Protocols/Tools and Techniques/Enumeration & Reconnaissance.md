Unlike remote execution, **most enumeration and recon tools do _not_ require administrative credentials.**

- Many of these can work with low-privileged domain users or even anonymous/null sessions (depending on configuration).
    
- **Admin creds can provide deeper access, but they are not mandatory.**
    
---
## rpcclient (Samba)

**Flow:**

1. Connects to a target’s **MSRPC interfaces** via SMB.
    
2. Talks to services like:
    
    - **SAMR** → enumerate users, groups.
        
    - **LSARPC** → policies, domain SID.
        
    - **Netlogon** → trust relationships.
        
3. Can work with:
    
    - Null sessions (if allowed).
        
    - Domain user credentials (broader results).
        

**Transport Stack:**  
`MSRPC over SMB named pipes (445) or TCP (135 depending on binding)`  

---

## smbclient / smbmap

**Flow:**

1. Connects to **SMB (445)**.
    
2. Enumerates available shares (`IPC$`, `C$`, `SYSVOL`, `NETLOGON`, etc.).
    
3. Queries share permissions (read/write).
    
4. Can list directory contents, pull files, or upload (if writeable).
    
5. Works with:
    
    - Null sessions (if allowed).
        
    - Domain creds for authenticated enumeration.
        

**Transport Stack:**  
`SMB (445/tcp)`

---

## enum4linux / enum4linux-ng

**Flow:**

1. Wrapper script around multiple Samba tools.
    
2. Uses:
    
    - **rpcclient** for user/group/domain enumeration.
        
    - **smbclient** for shares.
        
    - **LDAP (389/tcp)** for domain queries (if open).
        
3. Outputs consolidated domain info: users, groups, shares, policies.
    

**Transport Stack:**  
`SMB (445) + MSRPC + optionally LDAP (389/tcp)`

---

## BloodHound / PlumHound

**Flow:**

1. Collects information from a domain environment using **SharpHound** (or other collectors).
    
2. Data sources include:
    
    - **LDAP (389/tcp)** → users, groups, ACLs, trusts.
        
    - **SMB (445/tcp)** → sessions, local admins.
        
    - **MSRPC (135/tcp)** → group policy info.
        
3. Data is uploaded into BloodHound for graph analysis.
    
4. PlumHound adds automation/reporting for attack paths.
    

**Transport Stack:**  
`LDAP (389/tcp), SMB (445/tcp), MSRPC (135/tcp)