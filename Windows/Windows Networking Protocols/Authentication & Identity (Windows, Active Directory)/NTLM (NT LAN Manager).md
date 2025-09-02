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

# ⚠️ NTLM Attack Flows (Detailed)

## 1. 🔑 **Pass-the-Hash (PtH)**

**Goal:** Use stolen NT Hash instead of password.

**Flow:**

1. Attacker compromises a machine.
    
    - Dumps hashes via `lsass.exe`, `SAM`, or `NTDS.dit`.
        
    - Example: `mimikatz sekurlsa::logonpasswords`.
        
2. Attacker extracts the **NT Hash** (e.g., `aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99`).
    
3. Attacker uses a tool (`psexec.py`, `crackmapexec`, `wmiexec.py`) that forges the NTLM response:
    
    - Instead of computing `Encrypt(Challenge, Hash(password))` → they directly use the stolen hash.
        
4. Target server accepts the challenge-response as valid, because hash = password equivalent.
    

✅ Attacker authenticates to SMB, WMI, WinRM, or RPC **without ever knowing the password**.

---

## 2. 🔄 **NTLM Relay Attack**

**Goal:** Trick a victim into authenticating and relay their NTLM response to another service.

**Flow:**

1. Attacker poisons name resolution (LLMNR/mDNS/NBT-NS spoofing with `Responder`).
    
    - Victim asks: _“Who is FILESERVER?”_
        
    - Attacker responds: _“That’s me!”_
        
2. Victim sends NTLM Negotiate → Challenge → Authenticate to attacker.
    
3. Attacker doesn’t crack the hash — instead **relays the blobs** to a real target server (e.g., LDAP, SMB).
    
4. Target server verifies with DC → trusts attacker as the victim.
    

✅ Attacker gets **authenticated session** on the relay target, often with domain user privileges.

---

## 3. 🪪 **Pass-the-Ticket (NTLM Token Abuse)**

_(Different from Kerberos PtT — here it’s token theft)_

**Goal:** Reuse cached NTLM session tokens.

**Flow:**

1. Windows caches user tokens (in `lsass.exe`) for SSO.
    
2. Attacker dumps memory (e.g., Mimikatz `sekurlsa::tickets` or `sekurlsa::msv`).
    
3. Extracts NTLM session token (not just hash).
    
4. Injects token into own process (`token::elevate`).
    
5. OS accepts it → attacker impersonates user until token expiry.
    

✅ Used for **lateral movement** when Kerberos tickets aren’t available.

---

## 4. 💥 **Brute-Force / Cracking NTLM Hashes**

**Goal:** Recover plaintext password from NT Hash.

**Flow:**

1. Attacker obtains NTLM hash (same as PtH step 1).
    
2. Loads into cracking tool (`hashcat`, `john`).
    
3. Because NTLM = **unsalted MD4(password)**:
    
    - Pre-computed rainbow tables are effective.
        
    - GPU brute force is very fast (billions of guesses/sec).
        
4. Once cracked, attacker has the **cleartext password** → can authenticate via Kerberos, RDP, VPN, etc.
    

✅ Strong passwords resist, but weak/short ones fall quickly.

---

## 5. 📉 **NTLM Downgrade Attack**

**Goal:** Force system to use NTLM instead of Kerberos.

**Flow:**

1. Normally, domain clients prefer Kerberos (port 88).
    
2. Attacker blocks Kerberos traffic (e.g., drop/DoS to KDC).
    
3. Client retries using NTLM (fallback).
    
4. Attacker now applies **Relay** or **Pass-the-Hash**.
    

✅ Downgrade = enabler for other NTLM abuses.

---

## 6. ⏳ **NTLMv1 vs NTLMv2 Weakness**

- **NTLMv1**
    
    - Challenge response uses DES on only parts of the password hash.
        
    - Easily cracked with rainbow tables (`halflmchall`).
        
- **NTLMv2**
    
    - Uses HMAC-MD5 with challenge + timestamp.
        
    - Stronger, but still vulnerable to **Relay** (since server accepts relayed tokens blindly).
        

**Flow (NTLMv1 attack):**

1. Capture NTLMv1 handshake with `Responder`.
    
2. Crack offline in seconds/minutes with `hashcat -m 5500`.
    

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