NTLM is Microsoft’s **challenge–response authentication protocol**. It was designed before Kerberos and is still present in modern Windows for **backward compatibility**.

It does **not use tickets** (like Kerberos) but instead relies on proving knowledge of a password hash.

---

## 🧩 How NTLM Authentication Works

1. **Negotiate**
    
    - Client says: _“I support NTLM.”_
        
    - Server agrees.
        
2. **Challenge**
    
    - Server sends a random 16-byte **nonce** (`NTLM_CHALLENGE`).
        
3. **Authenticate**
    
    - Client calculates:
        
        `Response = Encrypt(Challenge, NT Hash)`
        
        where **NT Hash = MD4(UTF-16LE(password))**.
        
    - Client sends username + domain + response.
        
4. **Validation**
    
    - Server forwards this to the Domain Controller.
        
    - DC recomputes the expected response using the stored hash and compares.
        

👉 The **password is never sent**—only the challenge response.  
But the **hash itself is as good as the password**, which leads to attacks.

---

## ⚠️ Major NTLM Attacks

### 1. **Pass-the-Hash (PtH)**

- **Idea:** If you steal a user’s **NT Hash**, you don’t need the password.
    
- You can directly calculate responses to any challenge.
    
- Works because NTLM authentication only needs the hash, not the cleartext password.
    

**Steps:**

1. Attacker dumps hashes from a system (`lsass.exe`, `SAM`, `NTDS.dit`).
    
2. Uses the hash in tools like `Mimikatz`, `Impacket’s psexec.py`, or `crackmapexec`.
    
3. Authenticates to remote services (SMB, WMI, WinRM) **without knowing the password**.
    

---

### 2. **NTLM Relay Attack**

- Instead of cracking hashes, attacker **relays** the victim’s authentication to another service.
    
- No need to know the password/hash.
    

**Steps:**

1. Attacker runs `Responder` or `ntlmrelayx`.
    
2. Victim connects (e.g., via LLMNR/mDNS spoofing).
    
3. Attacker forwards challenge-response exchange to a target server.
    
4. Attacker is authenticated as the victim.
    

👉 Often used to pivot into LDAP/SMB to dump AD info.

---

### 3. **Pass-the-Ticket (NTLM Edition)**

_(more common in Kerberos, but NTLM also has token abuse)_

- Attacker steals a cached NTLM session token (Windows stores it in LSASS).
    
- Can impersonate the user until token expires.
    
---

### 4. **Brute Force / Cracking NTLM Hashes**

- Since NTLM hashes are unsalted **MD4(password)**, they can be brute-forced offline.
    
- Tools: `hashcat`, `John the Ripper`.
    
- Rainbow tables are effective against weak passwords.
    

---

### 5. **NTLM Downgrade**

- If Kerberos is available, Windows should prefer it.
    
- Attacker can trick client/server into **falling back to NTLM** (e.g., blocking Kerberos traffic).
    
- Now PtH or Relay attacks become possible.
    

---

### 6. **NTLMv1 vs NTLMv2 Weakness**

- **NTLMv1** (old) uses DES-based responses → very weak.
    
- **NTLMv2** (modern) is stronger (HMAC-MD5 + challenge + timestamp), but still relayable.
    
- Many attacks specifically target environments where NTLMv1 is still allowed.
    

---
## NTLM Transports

| Transport / Protocol               | Port(s)                 | How NTLM is Embedded                     |
| ---------------------------------- | ----------------------- | ---------------------------------------- |
| **SMB / CIFS**                     | 445/tcp, 139/tcp        | Inside Session Setup PDUs via NTLMSSP    |
| **RPC / MSRPC**                    | 135/tcp + dynamic ports | In RPC bind authentication context       |
| **HTTP (IWA/WebDAV/WinRM)**        | 80, 443, 5985, 5986     | In HTTP headers using NTLMSSP            |
| **LDAP / LDAPS**                   | 389, 636                | As a SASL bind mechanism                 |
| **SMTP / IMAP / POP3 / MSSQL**     | Varies                  | Protocol-independent NTLM authentication |
| **Cross-Protocol Relay Scenarios** | Various                 | NTLM blobs relayed across protocols      |

---
## 🛡️ Defenses Against NTLM Attacks

- **Disable NTLM where possible** (`Network security: Restrict NTLM`).
    
- **Enforce Kerberos** for domain authentication.
    
- **SMB Signing** to block NTLM relays.
    
- **Local admin isolation** (use LAPS to randomize local admin passwords).
    
- **Credential Guard / LSASS Protection** to stop hash theft.
    
- Monitor for unusual `NTLM` authentication events (`Event ID 4624` with Logon Type 3).
    

---

## 📡 Example in Wireshark

1. `Negotiate Protocol Request` → client offers NTLM.
    
2. `NTLMSSP_CHALLENGE` → server sends nonce.
    
3. `NTLMSSP_AUTH` → client responds with username + hashed response.
    

Filter:

`ntlmssp`

You’ll see fields like:

- `NTLMv2 Response`
    
- `Target Info`
    
- `Username`