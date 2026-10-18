---
title: "Kerberos Authentication Attacks in Active Directory"
created: 2026-03-11
type: technique
tags: [active-directory, network, protocols, technique, windows]
---

## What is Kerberos?

Kerberos is a **network authentication protocol**.  
It was designed at MIT in the 1980s (Project Athena) and is now the **default authentication system in Windows Active Directory**.

Its purpose is simple:  
➡️ Allow a user or computer to prove their identity **securely** to a service over an insecure network, without sending passwords.

---

## 📌 Key Concepts

- **Trusted Third Party (KDC):**
    
    - All authentication goes through a central authority called the **Key Distribution Center (KDC)**.
        
    - In Windows, the KDC runs on **Domain Controllers**.
        
- **Tickets, not Passwords:**
    
    - Instead of sending your password or hash each time, you get a **ticket** from the KDC.
        
    - You present that ticket to services (like SMB, LDAP, MSSQL).
        
    - Services trust the ticket because it’s cryptographically signed by the KDC.
        
- **Mutual Authentication:**
    
    - The service also proves itself back to you (so you know you’re not talking to an impostor).
        
---

## 📊 Kerberos Components

- **Client (User/Machine):** Wants to authenticate.
    
- **Service (Server):** What the client wants to access (SMB share, SQL DB, etc.).
    
- **KDC (on the DC):** Issues tickets.
    
    - **AS (Authentication Service):** Handles login.
        
    - **TGS (Ticket Granting Service):** Issues tickets for specific services.
        
- **krbtgt Account:** A special hidden account in AD whose password hash is used to sign TGTs.
## 1. 📡 Legitimate Kerberos Flow

**Actors:**

- **Client** (user workstation)
    
- **KDC (Key Distribution Center)** → runs on **Domain Controller**
    
    - **AS** (Authentication Service)
        
    - **TGS** (Ticket Granting Service)
        
- **Target Service** (e.g., SMB server, LDAP service, MSSQL)
    
**Port:** `88/tcp` and `88/udp` (Kerberos)

---

### 🧩 Step-by-Step

```text
# 🧩 Legitimate [[Kerberos Authentication Flow]] (Windows AD)

Actors:
- Client = Alice's machine
- KDC = Domain Controller (runs Kerberos AS + TGS)
- Target Service = Example: CIFS on fileserver01

Port: TCP/UDP 88 (Kerberos)

Step 1. Client → KDC (AS-REQ)
        "Hi, I’m Alice, I want to log in"
        Includes:
          - Alice's username
          - Realm (DOMAIN)
          - [If pre-auth enabled] Encrypted timestamp using Alice's password-derived key

        🧠 Pre-authentication: 
        Prevents offline brute-force attacks.
        The KDC requires Alice to encrypt the current timestamp using her password-derived key.
        If the timestamp decrypts correctly, the user is real.

Step 2. KDC → Client (AS-REP)
        "Here’s your Ticket Granting Ticket (TGT)"
        Includes:
          - Session Key (for KDC ↔ Client communication)
          - TGT = {
              Client: Alice
              Session Key
              Validity period
              PAC (privilege info)
            } encrypted with KDC's krbtgt account key

        🔒 Only the KDC can decrypt the TGT — it uses the krbtgt account's NT hash.
        🔑 The client can decrypt the session key because it was encrypted with Alice’s password-derived key.

Step 3. Client → KDC (TGS-REQ)
        "I have a TGT, now I want a ticket for CIFS/fileserver01"
        Includes:
          - TGT from Step 2
          - Authenticator = {
              Client name
              Timestamp
            } encrypted with TGT session key
          - SPN (Service Principal Name): cifs/fileserver01.DOMAIN

        🔐 Authenticator proves that the client knows the session key, and prevents replay.

Step 4. KDC → Client (TGS-REP)
        "Here’s your Service Ticket for CIFS/fileserver01"
        Includes:
          - Session Key2 (for Client ↔ Service)
          - Service Ticket = {
              Client name
              Session Key2
              Validity period
              PAC
            } encrypted with Service Account's key (e.g., fileserver01$)

        🧠 Only the service can decrypt the ticket — it’s encrypted with the service account’s password hash.

Step 5. Client → Target Service (AP-REQ)
        "Here’s my Service Ticket + proof I’m alive"
        Includes:
          - Service Ticket (from Step 4)
          - Authenticator = {
              Client name
              Timestamp
            } encrypted with Session Key2

        🔐 This proves to the service that the client is fresh and not replayed.

Step 6. Target Service → Client (AP-REP, optional)
        "I’m real too — here’s your timestamp + 1"
        - Only happens if mutual authentication is requested
        - Encrypted with Session Key2

Step 7. Target Service grants session.
        - The service uses the PAC inside the ticket to determine access control.
        - Alice now has a session as herself, authenticated via Kerberos.
```
---

### 🔍 What’s Inside

- **TGT (Ticket Granting Ticket)**
    
    - Encrypted with the **krbtgt account hash** (only DC can decrypt).
        
    - Proves the client authenticated.
        
- **Service Ticket**
    
    - Encrypted with the **service account hash** (e.g., CIFS/server01).
        
    - Only the target service can decrypt.
        
- **Authenticator**
    
    - Timestamp, session key — prevents replay.
        

---

## 2. ⚠️ Major Kerberos Attacks

---

### 1. 🟡 **Golden Ticket**

- Attacker steals **krbtgt account hash** from DC.
    
- Can forge their own TGTs for _any user_.
    
- Domain Controller will accept them because they decrypt correctly.
    

**Flow:**

```text
Attacker → forges TGT with krbtgt hash
Attacker → uses forged TGT in TGS-REQ
KDC → issues Service Ticket (because TGT looks legit)
Attacker → authenticates anywhere as any user
```

---

### 2. 🟠 **Silver Ticket**

- Attacker steals the **hash of a service account** (like SQLSvc or machine account).
    
- Forges a Service Ticket directly (no KDC involved).
    

**Flow:**

```text
Attacker → forges Service Ticket with service account hash Attacker → presents forged ticket to target service Target Service → accepts (ticket decrypts correctly)
```

- Stealthier than Golden Ticket (no DC contact).
    

---

### 3. 🔵 **Kerberoasting**

- Attacker requests Service Tickets for SPNs (Service Principal Names).
    
- These tickets are encrypted with the **service account’s NT hash**.
    
- Can be cracked offline to recover service account passwords.
    

**Flow:**

```text
Attacker → KDC: TGS-REQ for MSSQLSvc/server01
KDC → Attacker: TGS-REP (ticket encrypted with SQLSvc hash)
Attacker → cracks ticket offline with hashcat
```

---

### 4. 🟣 **Overpass-the-Hash / Pass-the-Key**

- Attacker uses a **NT hash** (from LSASS) to request Kerberos TGTs directly.
    
- Instead of injecting into NTLM, they inject into Kerberos.
    

**Flow:**

```text
Attacker (with NT hash) → mimikatz sekurlsa::pth
mimikatz requests TGT using hash as key
KDC → issues TGT
Attacker → uses Kerberos normally (tickets, services)
```

---

### 5. 🔻 **Kerberos Downgrade (Kerberoast/NTLM fallback)**

- Attacker forces client/server to fall back to NTLM (like we saw earlier).
    
- Or forces encryption downgrade (e.g., RC4 instead of AES).
    

---

## 3. 📡 Kerberos in Wireshark

Filters:

- `kerberos`
    

You’ll see:

- **AS-REQ / AS-REP** → login step
    
- **TGS-REQ / TGS-REP** → service request
    
- **AP-REQ / AP-REP** → actual service authentication
    

Fields to notice:

- `cname` (client username)
    
- `sname` (target service)
    
- `EncryptedTicket`