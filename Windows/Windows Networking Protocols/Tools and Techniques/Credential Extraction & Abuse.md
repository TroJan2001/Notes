Like remote execution, **credential extraction may or may not require administrative privileges** depending on the technique:

- **Local-only tools** (e.g., Mimikatz) require code execution on the machine with SYSTEM/SeDebugPrivilege.
    
- **Remote dumping** (e.g., secretsdump.py) requires domain admin or local admin rights.
    
- **Kerberos abuses** (e.g., roasting, brute force) usually need only a low-privileged domain account.
    
- **Pass-the-Hash / Overpass** need a stolen NTLM hash, not the plaintext password.

---

## Mimikatz

**Flow:**

1. Run locally on the target with high privileges (SYSTEM, SeDebugPrivilege).
    
2. Attaches to the **LSASS** process and extracts:
    
    - Plaintext passwords (if present).
        
    - NTLM hashes.
        
    - Kerberos tickets (TGT/TGS).
        
3. Can also **inject tickets** back into memory (Pass-the-Ticket, Golden Ticket).
    

- **Requires:**
    
    - Local execution on target.
        
    - High privileges (Administrator/SYSTEM).
        

**Example Commands:**

```bash
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::tickets
```

**Transport Stack:**  
`Local only (no network)`

---

## secretsdump.py (Impacket)

**Flow:**

1. **Authenticate remotely** with domain admin or local admin credentials.
    
2. Supports multiple dump methods:
    
    - **DRSUAPI**: Use Directory Replication Service to dump NTDS.dit (DC only).
        
    - **SAMR/LSARPC**: Extract local SAM hashes from registry over SMB.
        
    - **LSASS dump**: If admin rights, retrieve secrets remotely.
        
3. Hashes can be cracked offline or reused in Pass-the-Hash.
    

- **Requires:**
    
    - Domain Admin rights for DRSUAPI (DC replication).
        
    - Local admin rights for SAMR dumping.
        

**Example Commands:**

```bash
secretsdump.py domain/admin@dc01.domain.local
secretsdump.py localadmin@10.0.0.5
```

**Transport Stack:**  
`MSRPC over SMB (445/tcp)`

---

## Rubeus (GhostPack)

**Flow:**

1. Executes Kerberos-related actions:
    
    - Request or renew TGTs.
        
    - Extract tickets from memory.
        
    - Perform overpass-the-hash (NTLM → Kerberos TGT).
        
    - Inject forged tickets (Pass-the-Ticket, Golden Ticket).
        
2. Can perform **Kerberoasting** and **AS-REP Roasting** directly.
    

- **Requires:**
    
    - Domain creds (low-privilege account sufficient for roasting).
        
    - Elevated rights for ticket injection.
        

**Example Commands:**

```bash
Rubeus kerberoast
Rubeus asreproast
Rubeus ptt /ticket:<base64_ticket>
Rubeus asktgt /user:Administrator /rc4:<NTLM_hash>
```

**Transport Stack:**  
`Kerberos (88/tcp & udp)`

---

## Kerbrute

**Flow:**

1. Connects to the **KDC** (port 88).
    
2. Sends **AS-REQs** with different usernames:
    
    - Valid usernames → KDC responds with pre-auth required.
        
    - Invalid usernames → KDC returns error.
        
3. Supports password spraying and brute forcing via AS-REQ.
    

- **Requires:**
    
    - No domain admin rights.
        
    - Works with just connectivity to KDC.
        

**Example Commands:**

```bash
kerbrute userenum --dc 10.0.0.1 -d domain.local users.txt
kerbrute bruteuser --dc 10.0.0.1 -d domain.local users.txt 'Password123'
```

**Transport Stack:**  
`Kerberos (88/tcp & udp)`

---

## Kerberoasting

**Flow:**

1. Authenticated domain user requests a **TGS** for a Service Principal Name (SPN).
    
2. KDC returns the TGS encrypted with the service account’s NTLM hash.
    
3. Attacker extracts the TGS from memory or network capture.
    
4. Cracks the ticket offline to recover service account’s password.
    

- **Requires:** Any valid domain account (low privilege).
    

**Example Commands:**

```bash
# With Rubeus
Rubeus kerberoast /user:svc_sql /nowrap

# With Impacket
GetUserSPNs.py domain/user:password -dc-ip 10.0.0.1 -request
```

**Transport Stack:**  
`Kerberos (88/tcp)`

---

## AS-REP Roasting

**Flow:**

1. Find accounts with **“Do not require Kerberos preauthentication”** flag set.
    
2. Send AS-REQ for that user.
    
3. KDC returns an **AS-REP** encrypted with the user’s NTLM hash.
    
4. Crack offline to recover password.
    

- **Requires:** Any valid domain account (sometimes even anonymous if LDAP allows).
    

**Example Commands:**

```bash
# With Rubeus
Rubeus asreproast /user:roastableuser /nowrap

# With Impacket
GetNPUsers.py domain/ -usersfile users.txt -no-pass -dc-ip 10.0.0.1
```

**Transport Stack:**  
`Kerberos (88/tcp)`

---

## Pass-the-Hash (PtH)

**Flow:**

1. Obtain an NTLM hash of a user account (e.g., via Mimikatz or secretsdump).
    
2. Use the hash in place of the password during NTLM authentication.
    
3. Supported in tools like PsExec, SMBExec, WMIExec, CrackMapExec.
    
4. Target services (SMB, RPC, WinRM) accept the hash as if it were the password.
    

- **Requires:** Captured NTLM hash.
    

**Example Commands:**

```bash
psexec.py -hashes :aad3b435b51404eeaad3b435b51404ee,8846f7eaee8fb117ad06bdd830b7586c domain/Administrator@10.0.0.5
crackmapexec smb 10.0.0.0/24 -u Administrator -H <NTLM_hash>
```
**Transport Stack:**  
`SMB (445), RPC (135), WinRM (5985/5986)`

---

## Pass-the-Ticket (PtT)

**Flow:**

1. Steal a valid Kerberos ticket (TGT/TGS) from memory.
    
2. Inject the ticket into another session.
    
3. Use it to access resources until it expires.
    

- **Requires:** A valid Kerberos ticket.
    

**Example Commands:**

```bash
mimikatz # kerberos::ptt ticket.kirbi
```
**Transport Stack:**  
`Kerberos (88/tcp)`

---

## Overpass-the-Hash (a.k.a. Pass-the-Key)

**Flow:**

1. Use an NTLM hash to request a Kerberos TGT from the KDC.
    
2. Get Kerberos tickets without knowing the password.
    
3. Pivot from NTLM into full Kerberos authentication.
    

- **Requires:** NTLM hash of a domain account.
    

**Example Commands:**

```bash
mimikatz # sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:<NTLM_hash>
Rubeus asktgt /user:Administrator /rc4:<NTLM_hash> /domain:domain.local
```

**Transport Stack:**  
`Kerberos (88/tcp)`

## Silver Ticket

**Flow:**

1. Steal the **NTLM hash of a service account** (e.g., SQL service, IIS app pool, computer account).
    
2. Forge a **Service Ticket (TGS)** using that hash.
    
3. Present the fake TGS directly to the service (CIFS, HTTP, MSSQL, etc.).
    
    - No contact with the Domain Controller.
        
4. Access that specific service as any user you choose.
    

- **Requires:** Service account NTLM hash.
    
- **Impact:** Limited to one service, but stealthy since DC never sees the request.
    

**Example Commands:**

```bash
# Mimikatz example
mimikatz # kerberos::golden /user:attacker /domain:domain.local /sid:S-1-5-21-... \
/target:host.domain.local /service:cifs /rc4:<service_NTLM_hash> /id:500
```

**Transport Stack:**  
`Kerberos (88/tcp)`

---

## Golden Ticket

**Flow:**

1. Dump the **krbtgt account hash** from a Domain Controller (requires DA initially).
    
2. Forge your own **Ticket Granting Tickets (TGTs)** for _any user_ in the domain.
    
3. Since the TGT is encrypted/signed with krbtgt’s hash, the DC accepts it as valid.
    
4. Use forged TGTs to request TGS tickets for any service.
    
5. Persistence: works until krbtgt password is changed (usually very rare).
    

- **Requires:** krbtgt account NTLM hash (Domain Admin level compromise).
    
- **Impact:** Full domain compromise with indefinite persistence.
    

**Example Commands:**

```bash
# Mimikatz example
mimikatz # kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... \
/krbtgt:<krbtgt_NTLM_hash> /id:500
```

**Transport Stack:**  
`Kerberos (88/tcp)`

## Potential Attack Flow:

### 1. **Initial Cred Discovery**

- **Kerbrute** → enumerate valid usernames, spray passwords.
    
- **AS-REP Roasting** → if “Do not require pre-auth” is set, crackable AS-REPs.
    
- **Kerberoasting** → request service tickets with low-priv user, crack offline.
    

👉 _Goal: get a valid domain user credential or service account hash._

---

### 2. **Dumping & Extraction**

- **Mimikatz** (local execution) → dump creds/hashes/tickets from LSASS.
    
- **secretsdump.py** (remote) → extract NTDS.dit or SAM hashes if admin.
    
- **Rubeus** → pull Kerberos tickets, request new TGTs.
    

👉 _Goal: escalate from one compromised host or user → capture more creds._

---

### 3. **Credential Reuse**

- **Pass-the-Hash (PtH)** → reuse NTLM hash against SMB/RPC/WinRM.
    
- **Pass-the-Ticket (PtT)** → inject stolen Kerberos tickets.
    
- **Overpass-the-Hash** → turn NTLM hash into Kerberos TGT (pivot NTLM → Kerberos).
    

👉 _Goal: laterally move inside the network using stolen creds/tickets._

---

### 4. **Ticket Forgery (Persistence / Privilege Escalation)**

- **Silver Ticket** → forge service tickets with service account hash (stealthy, DC not contacted).
    
- **Golden Ticket** → forge TGTs with `krbtgt` hash (full domain persistence).
    

👉 _Goal: maintain long-term access and impersonate anyone indefinitely._