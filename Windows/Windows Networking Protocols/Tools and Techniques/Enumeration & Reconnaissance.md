Unlike remote execution, **most enumeration and recon tools do _not_ require administrative credentials.**

- Many can work with **low-privileged domain users** or even **anonymous/null sessions** (if allowed).
    
- **Admin creds** can reveal more data but are not mandatory.
   
---
## rpcclient (Samba)

**Flow:**

1. Connects to a target’s **MSRPC interfaces**.
    
    - Via **SMB named pipes (445)** or
        
    - Direct **MSRPC over TCP (135)** depending on binding.
        
2. Talks to services like:
    
    - **SAMR** → enumerate users, groups, RID cycling.
        
    - **LSARPC** → domain SID, policy info.
        
    - **Netlogon** → trust relationships.
        
3. Can work with:
    
    - Null sessions (if allowed).
        
    - Domain creds (more detail).
        

**Transport Stack:**  
`MSRPC over SMB named pipes (445) or MSRPC over TCP (135)`

---

## RID Cycling (Technique)

**Flow:**

1. Abuse SAMR interface with sequential RID lookups.
    
2. Each RID → account name, even without valid creds (if null sessions allowed).
    
3. Builds a list of domain users and groups.
    

**Transport Stack:**  
`MSRPC (SAMR) over SMB (445)`

---

## smbclient / smbmap

**Flow:**

1. Connects to **SMB (445)**.
    
2. Enumerates shares (`IPC$`, `SYSVOL`, `NETLOGON`, `C$`, etc.).
    
3. Lists permissions, browses directories, pulls files, uploads if writeable.
    
4. Works with:
    
    - Null sessions.
        
    - Authenticated domain creds.
        

**Transport Stack:**  
`SMB (445/tcp)`

---

## enum4linux / enum4linux-ng

**Flow:**

1. Wrapper script around multiple Samba tools.
    
2. Uses:
    
    - **rpcclient** for users, groups, RIDs.
        
    - **smbclient** for shares.
        
    - **net / nmblookup** for host discovery.
        
    - **LDAP (389/tcp)** for AD queries.
        
3. Consolidates into domain info dump.
    

**Transport Stack:**  
`SMB (445) + MSRPC + optionally LDAP (389)`

---

## ldapsearch

**Flow:**

1. Standard OpenLDAP client.
    
2. Queries AD LDAP (389) or LDAPS (636).
    
3. Enumerates:
    
    - Users, groups, computers.
        
    - Policies and attributes.
        
    - Trust relationships.
        
4. Requires at least a valid domain user (unless anonymous LDAP binds are enabled).
    

**Transport Stack:**  
`LDAP (389/tcp) or LDAPS (636/tcp)`

---

## nxc (NetExec / CME)

**Flow:**

1. Multipurpose framework (successor of CrackMapExec).
    
2. Can:
    
    - Enumerate users, shares, sessions.
        
    - Spray credentials across many hosts.
        
    - Execute commands via SMB, WMI, WinRM.
        
3. Serves both **Recon** and **Remote Execution**, but often used first for mapping.
    

**Transport Stack:**  
`SMB (445), MSRPC (135), WinRM (5985/5986), WMI (135)`

---

## BloodHound / PlumHound

**Flow:**

1. Collects AD data using SharpHound or other collectors.
    
2. Sources include:
    
    - **LDAP** → users, groups, ACLs, trusts.
        
    - **SMB** → active sessions, local admin rights.
        
    - **MSRPC** → GPOs, services.
        
3. Data ingested into graph DB for attack path analysis.
    
4. PlumHound automates reporting and queries.
    

**Transport Stack:**  
`LDAP (389), SMB (445), MSRPC (135)`