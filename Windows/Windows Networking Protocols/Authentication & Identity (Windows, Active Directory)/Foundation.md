Windows networks rely on **authentication protocols** (to prove _who you are_) and **directory services** (to check _what you can access_). These work together under **Active Directory (AD)**.

├── Authentication & Identity  
│ • NTLM (challenge–response)  
│ • Kerberos (ticket-based, 88/tcp/udp)  
│ • LDAP (389/636, AD directory queries)  

---

## 🔹 NTLM (NT LAN Manager)

**Type:** Challenge–Response protocol  
**Ports Used:** Runs inside SMB (445/tcp) or RPC, not standalone  
**Default:** Used only when Kerberos is unavailable

### 🧩 How It Works

1. **Negotiate** – Client and server agree to use NTLM.
    
    - Example: SMB packet with `Negotiate Protocol Request`.
        
2. **Challenge** – Server sends a random 16-byte value (`NTLM_CHALLENGE`).
    
3. **Authenticate** – Client encrypts the challenge using the user’s password hash and sends it back.
    
4. **Validation** – Server checks with the Domain Controller (if joined).
    

### 📡 Packet Example (SMB session setup)

- Server sends `NTLM_CHALLENGE` (contains nonce).
    
- Client responds with `NTLM_AUTHENTICATE` (contains username, domain, response).
    

> In Wireshark: Filter `ntlmssp` → you’ll see fields like `NTLMv2 Response` and `Target Info`.

### ⚠️ Security Issues

- Password is never sent, but the **hash is enough** to replay → **Pass-the-Hash** attack.
    
- No mutual authentication → vulnerable to MITM (e.g., `responder.py` attacks).
    
- Still present for backward compatibility.

---

## 🔹 Kerberos

**Type:** Ticket-based protocol (shared secret + symmetric crypto)  
**Port:** `88/tcp` and `88/udp`  
**Default in AD:** Yes (preferred over NTLM since Windows 2000)  
**Authority:** Domain Controller runs the **KDC (Key Distribution Center)**

### 🧩 Flow

1. **AS-REQ / AS-REP**
    
    - Client requests a **TGT (Ticket Granting Ticket)** from KDC.
        
    - Encrypted with user’s long-term key (derived from password).
        
2. **TGS-REQ / TGS-REP**
    
    - Client uses TGT to request a **Service Ticket** for a specific service (e.g., CIFS, LDAP).
        
3. **AP-REQ / AP-REP**
    
    - Client presents Service Ticket to the server.
        
    - Optional: Server returns AP-REP for mutual authentication.
        

### 📡 Packet Example

- Filter `kerberos` in Wireshark.
    
- You’ll see `AS-REQ` containing client principal name (username) and realm (domain).
    
- `TGS-REP` will show an encrypted blob = the service ticket.
    

### ⚠️ Security Notes

- **Golden Ticket** – forged TGT with `krbtgt` hash = impersonate anyone.
    
- **Silver Ticket** – forged service ticket = access one service directly.
    
- Tickets cached locally (`klist` in Windows).
    

### ✅ Benefits

- Strong cryptography, replay protection (timestamps).
    
- Mutual authentication (prevents MITM).
    
- Scales better than NTLM in large environments.
    

---

## 🔹 LDAP (Lightweight Directory Access Protocol)

**Purpose:** Querying and modifying directory services (like AD DS).  
**Ports:**

- `389/tcp` → LDAP (cleartext)
    
- `636/tcp` → LDAPS (over SSL/TLS)
    
- `3268/tcp` → Global Catalog queries (across domains)
    

### 🧩 Common Use Cases

- Login lookups (`bind` operation with username+password).
    
- Checking group membership.
    
- Applications binding to AD to authenticate users.
    
- Replication and directory browsing.
    

### 📡 Packet Example

- Filter `ldap` in Wireshark.
    
- Example:
    
    - `bindRequest` → client authenticates (can be simple cleartext, or SASL/NTLM, or Kerberos).
        
    - `searchRequest` → query for `(&(objectClass=user)(sAMAccountName=jdoe))`.
        
    - `searchResEntry` → returns user attributes (cn, mail, memberOf, etc.).
        

### ⚠️ Security Notes

- If only LDAP/389 is used → passwords are transmitted in **cleartext** during simple binds.
    
- **Anonymous binds** (default disabled in AD) can leak directory info.
    
- Enforce **LDAPS** or **StartTLS** for security.
    

---

## 📊 Comparison Table

|Protocol|Function|Default AD Role|Risks / Abuse|
|---|---|---|---|
|**NTLM**|Challenge–response auth|Legacy / fallback|Pass-the-Hash, MITM (responder)|
|**Kerberos**|Ticket-based authentication|Default domain auth|Golden/Silver Ticket, ticket theft|
|**LDAP**|Directory queries & binds|AD queries (389/636)|Cleartext binds, anonymous queries|

---

## 🔍 Tips

- **Wireshark filters**:
    
    - `ntlmssp` → see NTLM challenge/response.
        
    - `kerberos` → see AS/TGS exchanges.
        
    - `ldap` → see queries and results.
        
- Demonstrate fallback:
    
    - Disable Kerberos → watch NTLM take over in SMB authentication.
        
    - Use `ldapsearch` on Linux or `ldp.exe` on Windows to show directory queries.