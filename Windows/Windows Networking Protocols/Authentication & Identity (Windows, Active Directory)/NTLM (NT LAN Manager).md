NTLM is Microsoft’s **challenge–response authentication protocol**. It was designed before Kerberos and is still present in modern Windows for **backward compatibility**.

It does **not use tickets** (like Kerberos) but instead relies on proving knowledge of a password hash.

---

# 🔐 Legitimate NTLM Authentication Flow

**Actors:**

- **Client** (the user’s workstation or application)
    
- **Server** (the resource: SMB file server, HTTP server, SQL server, etc.)
    
- **Domain Controller (DC)** (if domain-joined; otherwise the server validates locally)
    

**Ports / Transport:**

- SMB (445/tcp or 139/tcp)
    
- RPC (135/tcp + dynamic)
    
- HTTP (80/443, WebDAV/WinRM)
    
- LDAP (389/636)
    
- Other apps (MSSQL, mail protocols, etc.)
    

NTLM is carried **inside these protocols** using the `NTLMSSP` (NTLM Security Support Provider).

---

## 🧩 Detailed Flow (NTLMv2)

### 1. **Negotiate Message (from Client → Server)**

- The client starts by sending a message saying:
    
    - “I support NTLM”
        
    - Lists capabilities (e.g., NTLMv1/NTLMv2, session security options).
        

📡 Example inside SMB2 `Session Setup Request`:

`NTLMSSP_NEGOTIATE   Flags: NTLMv2, 128-bit encryption, signing`

---
### 2. **Challenge Message (from Server → Client)**

- Server responds with:
    
    - A **random 8 or 16-byte nonce** (the “challenge”)
        
    - Target information (domain name, NetBIOS name, etc.)
        

📡 Example inside SMB2 `Session Setup Response`:

`NTLMSSP_CHALLENGE   ServerChallenge: 0x1122334455667788   TargetInfo: DOMAIN\SERVER`

---

### 3. **Authenticate Message (from Client → Server)**

- The client now proves it knows the user’s password hash.
    
- Steps:
    
    1. Compute **NT Hash** = `MD4(UTF-16-LE(password))`.
        
    2. Derive **NTLMv2 hash** = `HMAC-MD5(NT Hash, Username + Domain)`.
        
    3. Compute **NTLMv2 Response** = `HMAC-MD5(NTLMv2 hash, ServerChallenge + ClientNonce + Timestamp + TargetInfo)`.
        
    4. Send:
        
        - Username
            
        - Domain name
            
        - NTLMv2 Response blob
            

📡 Example inside SMB2 `Session Setup Request`:

`NTLMSSP_AUTHENTICATE   User: Alice   Domain: ACME   NTLMv2 Response: <16-byte HMAC + client data>`

---

### 4. **Validation (Server → DC)**

- The server itself usually doesn’t know the user’s password.
    
- So it **forwards the username + challenge + response** to the **Domain Controller** (via Netlogon RPC).
    
- The DC:
    
    1. Looks up the stored hash for the user in AD.
        
    2. Recomputes the expected response using the same math.
        
    3. If they match → authentication succeeds.
        

📡 RPC call: `NetrLogonSamLogonEx` with NTLM challenge/response.

---

### 5. **Result**

- DC returns success/failure.
    
- Server tells the client “Access granted” or “Access denied.”
    
- If granted, the client gets a session token (access token) tied to that identity.
    

---

## 📊 Summary (Message Flow)

[Client] → [Server]       NTLM NEGOTIATE
[Server] → [Client]       NTLM CHALLENGE (nonce)
[Client] → [Server]       NTLM AUTHENTICATE (username + HMAC response)
[Server] → [DC]           Validate with stored hash (if domain joined)
[DC]     → [Server]       OK / Fail (if domain joined)
[Server] → [Client]       Access granted/denied

---

# ⚠️ NTLM Attack Flows (Detailed)

## 🔑 Attack 1: Pass-the-Hash (PtH)

Actors:

- **Attacker** (already compromised machine, has stolen NT Hash)
    
- **Target Server**
    
- **DC**
    

```text
Step 0. Attacker compromises workstation, dumps NT Hash of Alice.

Step 1. Attacker → Target Server: NTLM NEGOTIATE
         "I want to log in as Alice"

Step 2. Target Server → Attacker: NTLM CHALLENGE
         "Here’s my random nonce"

Step 3. Attacker (forges response with stolen NT Hash):
         Response = HMAC(ServerNonce, Alice_NT_Hash)

Step 4. Attacker → Target Server: NTLM AUTHENTICATE
         "Alice + forged response"

Step 5. Target Server → DC: Validate
Step 6. DC → Target Server: OK
Step 7. Target Server → Attacker: Access granted (as Alice)
```

👉 Why it works: the hash _is_ the password equivalent. The DC doesn’t know this is forged — it just recomputes with the stored hash and sees a match.

---

## 🔄 Attack 2: NTLM Relay

Actors:

- **Victim Client** (legitimate domain user)
    
- **Attacker/MITM** (Responder/ntlmrelayx)
    
- **Target Server** (e.g., LDAP, SMB)
    
- **DC**
    
---
### Why does the Victim Authenticate?

Because Windows services **automatically try to authenticate** when connecting to a resource that looks like a file share, printer, or HTTP site using “Integrated Windows Authentication (IWA).”

The attacker tricks the victim into connecting:

- **LLMNR/NBT-NS spoofing**: Victim looks for `\\fileserver\share`, attacker answers “that’s me.”
    
- **Malicious link/email**: Victim clicks `\\ATTACKER\share`.
    
- **Rogue HTTP site**: Victim browses to site that requests NTLM auth.
    

Windows will automatically send NTLM credentials without asking the user (single sign-on).

---

### Full Relay Flow

```text
Step 1. Victim Client → Attacker: NTLM NEGOTIATE
         (Victim thinks Attacker = FILESERVER)

Step 2. Attacker → Target Server: NTLM NEGOTIATE
         (Forwards Victim’s negotiate to real server)

Step 3. Target Server → Attacker: NTLM CHALLENGE
Step 4. Attacker → Victim Client: NTLM CHALLENGE
         (Forwards challenge to Victim)

Step 5. Victim Client → Attacker: NTLM AUTHENTICATE
         "Here is my username + HMAC(TargetNonce, NT Hash)"

Step 6. Attacker → Target Server: NTLM AUTHENTICATE
         (Forwards Victim’s authenticate)

Step 7. Target Server → DC: Validate Victim’s response
Step 8. DC → Target Server: OK
Step 9. Target Server → Attacker: Access granted (as Victim)
```

👉 The **victim never knows** this happened. They were tricked into authenticating because:

- Windows will happily send NTLM when connecting to file shares, HTTP sites, etc.
    
- The attacker “posed” as that service (via spoofing or redirection).
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