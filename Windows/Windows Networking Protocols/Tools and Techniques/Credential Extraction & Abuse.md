like remote execution, **credential extraction may or may not require administrative privileges** depending on the technique.

- **Local-only tools** (e.g., Mimikatz) require code execution on the machine with sufficient privileges (often SYSTEM or debug rights).
    
- **Remote dumping** (e.g., secretsdump.py) requires domain admin or equivalent rights if targeting a DC.
    
- **Kerberos abuses** (e.g., roasting, brute force) often require only a low-privileged domain account.
    
- **Pass-the-Hash** requires a stolen NTLM hash but not the cleartext password.
    

---

## Mimikatz

**Flow:**

1. Run locally on the target with high privileges (SYSTEM, SeDebugPrivilege).
    
2. Attaches to the **LSASS** process and extracts:
    
    - Plaintext passwords (if present).
        
    - NTLM hashes.
        
    - Kerberos tickets (TGT/TGS).
        
3. Can also **inject tickets** back into memory (Pass-the-Ticket, Golden Ticket).
    

- Requires:
    
    - Local execution on target.
        
    - High privileges (Administrator/SYSTEM).
        

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
    

- Requires:
    
    - Domain Admin rights for DRSUAPI (DC replication).
        
    - Local admin rights for SAMR dumping.
        

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
        
2. Can perform **Kerberoasting** directly.
    

- Requires:
    
    - Domain creds (low-privilege account sufficient for roasting).
        
    - Elevated rights for ticket injection.
        

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
    

- Requires:
    
    - No domain admin rights.
        
    - Works with just connectivity to KDC.
        

**Transport Stack:**  
`Kerberos (88/tcp & udp)`

---

## Kerberoasting

**Flow:**

1. Authenticated domain user requests a **TGS** for a Service Principal Name (SPN).
    
2. KDC returns the TGS encrypted with the service account’s NTLM hash.
    
3. Attacker extracts the TGS from memory (e.g., Rubeus) or packet capture.
    
4. Cracks the ticket offline to recover service account’s password.
    

- Requires:
    
    - Any valid domain account (low privilege).
        

**Transport Stack:**  
`Kerberos (88/tcp)`

---

## AS-REP Roasting

**Flow:**

1. Find accounts with **“Do not require Kerberos preauthentication”** flag set.
    
2. Send AS-REQ for that user.
    
3. KDC returns an **AS-REP** encrypted with the user’s NTLM hash.
    
4. Crack offline to recover password.
    

- Requires:
    
    - Any valid domain account to query, or sometimes anonymous if LDAP allows enumeration.
        

**Transport Stack:**  
`Kerberos (88/tcp)`

---

## Pass-the-Hash (PtH)

**Flow:**

1. Obtain an NTLM hash of a user account (e.g., via Mimikatz or secretsdump).
    
2. Use the hash in place of the password during NTLM authentication.
    
3. Supported in tools like:
    
    - Impacket PsExec, SMBExec, WMIExec.
        
    - CrackMapExec / NetExec.
        
    - Metasploit modules.
        
4. Target services (SMB, RPC, WinRM) accept the hash as if it were the password.
    

- Requires:
    
    - Captured NTLM hash.
        
    - No need to know the plaintext password.
        

**Transport Stack:**  
`SMB (445), RPC (135), WinRM (5985/5986)`