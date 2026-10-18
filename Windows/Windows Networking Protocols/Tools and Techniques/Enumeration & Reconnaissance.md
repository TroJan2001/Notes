Unlike remote execution, **most enumeration and recon tools do _not_ require administrative credentials.**

- Many work with **low-privileged domain users** or even **anonymous/null sessions** (if allowed).
    
- **Admin creds** reveal more data but are not mandatory.
    

---

## rpcclient (Samba)

**Flow:**

1. Connect to target’s **MSRPC interfaces**
    
    - Over **SMB named pipes (445)**, or
        
    - Directly via **MSRPC over TCP (135)**.
        
2. Query services such as:
    
    - **SAMR** → enumerate users, groups, RID cycling.
        
    - **LSARPC** → domain SID, policy info.
        
    - **Netlogon** → trust relationships.
        
3. Works with:
    
    - Null sessions (if permitted).
        
    - Domain creds (more detailed output).
        

**Requires:** Null session or valid domain creds.

**Example Commands:**

```bash
rpcclient -U "" -N 10.0.0.5         # Null session
rpcclient -U domain/user 10.0.0.5   # With creds
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> queryuser 0x3e9         # RID lookup
```
**Transport Stack:**  
`MSRPC over SMB (445) or MSRPC over TCP (135)`

---

## RID Cycling (Technique)

**Flow:**

1. Abuse **SAMR** interface with sequential RID lookups.
    
2. Each RID reveals account name (user/group).
    
3. Builds full list of domain users/groups.
    

**Requires:** Null session or low-priv user (if SAMR allows).

**Example Commands:**

```bash
rpcclient -U "" -N 10.0.0.5
rpcclient $> lookupsids S-1-5-21-111111111-222222222-333333333-500-1000-1100
```
**Transport Stack:**  
`MSRPC (SAMR) over SMB (445)`

---

## smbclient / smbmap

**Flow:**

1. Connect to **SMB (445)**.
    
2. Enumerate available shares (`IPC$`, `SYSVOL`, `NETLOGON`, `C$`, etc.).
    
3. List permissions, browse directories, pull/upload files (if allowed).
    
4. Works with:
    
    - Null sessions.
        
    - Authenticated creds.
        

**Requires:** Null session or valid domain creds.

**Example Commands:**

```bash
smbclient -L //10.0.0.5/ -N
smbclient //10.0.0.5/IPC$ -U domain/user
smbmap -H 10.0.0.5 -u '' -p ''      # Null session
smbmap -H 10.0.0.5 -u user -p pass  # Auth
```

**Transport Stack:**  
`SMB (445/tcp)`

---

## enum4linux / enum4linux-ng

**Flow:**

1. Wrapper script around multiple Samba tools.
    
2. Uses:
    
    - **rpcclient** for users/groups/RIDs.
        
    - **smbclient** for shares.
        
    - **net / nmblookup** for host discovery.
        
    - **LDAP (389/tcp)** for AD queries.
        
3. Consolidates into single domain info dump.
    

**Requires:** Null session or valid domain creds.

**Example Commands:**

```bash
enum4linux -a 10.0.0.5
enum4linux-ng -A 10.0.0.5 -u user -p pass -d domain.local
```

**Transport Stack:**  
`SMB (445) + MSRPC + optionally LDAP (389)`

---

## Impacket Enumeration Scripts

**Flow:**

1. Python scripts that interact with MSRPC/SMB/LDAP.
    
2. Examples:
    
    - **samrdump.py** → enumerate domain users/groups.
        
    - **lookupsid.py** → SID → username resolution.
        
    - **GetUserSPNs.py** → find service accounts (Kerberos SPNs).
        
3. Useful for enumeration without needing full exploitation.
    

**Requires:** Null session or valid domain creds (depending on script).

**Example Commands:**

```bash
samrdump.py domain/user:pass@10.0.0.5
lookupsid.py domain/user:pass@10.0.0.5
GetUserSPNs.py domain/user:pass@dc01.domain.local
```

**Transport Stack:**  
`SMB (445), MSRPC (135), Kerberos (88)`

---

## Keimpx

**Flow:**

1. Validate credentials or hashes across multiple SMB hosts.
    
2. Enumerate accessible shares once authentication works.
    

**Requires:** Valid creds or NTLM hash.

**Example Commands:**

```bash
keimpx -u user -p pass -H 10.0.0.5
keimpx -U users.txt -P passwords.txt -h 10.0.0.5
```

**Transport Stack:**  
`SMB (445)`

---

## Nmap NSE (Nmap Scripting Engine) Scripts for Enumeration

**Flow:**

1. Automates enumeration of SMB/LDAP using scripts.
    
2. Examples:
    
    - **SMB** → `smb-enum-shares.nse`, `smb-os-discovery.nse`.
        
    - **LDAP** → `ldap-search.nse`, `ldap-brute.nse`.
        
3. Can check for vulnerabilities and OS info too.
    

**Requires:** Null session or valid domain creds (depending on script).

**Example Commands:**

```bash
# SMB shares
nmap --script smb-enum-shares.nse -p 445 <target>

# LDAP info
nmap --script ldap-search.nse -p 389 <target>

# LDAP brute-force
nmap --script ldap-brute.nse -p 389 --script-args userdb=users.txt,passdb=passwd.txt <target>
```
**Transport Stack:**  
`SMB (445), LDAP (389), LDAPS (636)`

---

## ldapsearch

**Flow:**

1. Query Active Directory over LDAP (389) or LDAPS (636).
    
2. Enumerate:
    
    - Users, groups, computers.
        
    - Policies, trusts, attributes.
        
3. Works with:
    
    - Domain user creds (usually).
        
    - Anonymous bind (if allowed).
        

**Requires:** Valid domain user (or anonymous if allowed).

**Example Commands:**

```bash
ldapsearch -x -H ldap://10.0.0.5 -D "domain\user" -w 'Password123' -b "dc=domain,dc=local"
ldapsearch -x -H ldap://10.0.0.5 -b "dc=domain,dc=local"   # Try anonymous
```

**Transport Stack:**  
`LDAP (389/tcp) or LDAPS (636/tcp)`

---

## Manspider / SMBcrunch

**Flow:**

1. Crawl SMB shares for interesting files.
    
2. Search for keywords like “password”, “secret”, “key”, etc.
    
3. Helps find sensitive data inside large shares.
    

**Requires:** Null session or valid domain creds.

**Example Commands:**

```bash
manspider.py 10.0.0.5 -u user -p pass --pattern "password"
smbcrunch -H 10.0.0.5 -u user -p pass -p "secret"
```
**Transport Stack:**  
`SMB (445)`

---

## CrackMapExec (CME)

**Flow:**

1. Multipurpose framework for **AD enumeration + execution**.
    
2. Can:
    
    - Enumerate users, shares, sessions.
        
    - Spray creds across subnets.
        
    - Pass-the-Hash, Kerberos relay.
        
    - Execute commands via SMB, WMI, WinRM.
        

**Requires:** Null session (basic), valid creds or hashes for advanced features.

**Example Commands:**

```bash
crackmapexec smb 10.0.0.5 -u '' -p ''         # Null session
crackmapexec smb 10.0.0.5 -u user -p pass --shares
crackmapexec smb 10.0.0.0/24 -u users.txt -p 'Password123'
crackmapexec smb 10.0.0.5 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

**Transport Stack:**  
`SMB (445), MSRPC (135), WinRM (5985/5986), WMI (135), Kerberos (88)`

---

## NetExec (nxc)

**Flow:**

1. Modern successor framework (similar to CME).
    
2. Faster + modular, supports plugins.
    
3. Can:
    
    - Enumerate shares, users, sessions.
        
    - Credential spraying.
        
    - Remote execution via SMB/WMI/WinRM.
        

**Requires:** Null session or valid domain creds/hashes.

**Example Commands:**

```bash
nxc smb 10.0.0.5 --shares
nxc smb 10.0.0.0/24 -u users.txt -p passwords.txt
nxc smb 10.0.0.5 -u user -p pass --exec-method smbexec
```

**Transport Stack:**  
`SMB (445), MSRPC (135), WinRM (5985/5986), WMI (135)`

---

## BloodHound / SharpHound / PlumHound

**Flow:**

1. Collect AD data (via SharpHound collector).
    
2. Sources:
    
    - **LDAP** → users, groups, trusts, ACLs.
        
    - **SMB** → active sessions, local admin rights.
        
    - **MSRPC** → GPOs, services.
        
3. Data ingested into Neo4j graph DB → find attack paths.
    
4. PlumHound automates queries/reporting.
    

**Requires:** Domain creds (low-priv enough).

**Example Commands:**

```bash
Invoke-BloodHound -CollectionMethod All
SharpHound.exe -c All
```

**Transport Stack:**  
`LDAP (389), SMB (445), MSRPC (135)`

---

## Kerberos Tools (Kerbrute / Rubeus)

**Flow:**

1. Enumerate domain accounts and tickets.
    
2. **Kerbrute** → brute-force / spray usernames and passwords via AS-REQ.
    
3. **Rubeus** → Kerberoasting, AS-REP roasting, ticket extraction.
    
4. Useful for finding valid accounts + service accounts.
    

**Requires:**

- No creds (for Kerbrute userenum).
    
- Valid low-priv domain account (for roasting).
    

**Example Commands:**

```bash
kerbrute userenum --dc 10.0.0.1 -d domain.local users.txt
```

**Transport Stack:**  
`Kerberos (88/tcp & udp)`