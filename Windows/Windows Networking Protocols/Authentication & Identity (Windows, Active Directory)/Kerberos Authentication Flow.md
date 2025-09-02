### ✅ Step 1: AS-REQ — Alice logs into the domain

🧑 **Alice → KDC (UDP/88 or TCP/88)**

```text
AS-REQ:
  cname: alice
  realm: DOMAIN.LOCAL
  pre-auth data:
    encrypted_timestamp = Enc(Timestamp, key=MD4(UTF-16LE("AlicePassword")))
```

🧠 This says:

> "Hey KDC, I’m Alice. Here’s an encrypted timestamp proving I know my password."

✅ Pre-authentication is enabled → so Alice has to prove knowledge of her password-derived key before getting any ticket.

---

### ✅ Step 2: AS-REP — KDC responds with TGT

🖥️ **KDC → Alice**

```text
AS-REP:
  Encrypted part (with Alice’s password key):
    session_key = K_s
    tgt_lifetime = 10h
  Ticket Granting Ticket (TGT):
    {
      client: alice
      session_key = K_s
      validity: 10h
      PAC: SID, groups, privileges
    } encrypted with krbtgt hash
```

🧠 TGT is opaque to Alice — she can’t decrypt it. It’s just proof of who she is, signed by the DC.  
K_s is the shared secret for talking to the KDC in the next step.

✅ Alice stores the TGT and session key in memory (LSASS/kerberos cache).

---

### ✅ Step 3: TGS-REQ — Alice wants access to a service

🧑 **Alice → KDC**

```text
TGS-REQ:
  tgt = (TGT from before)
  authenticator = {
    cname: alice
    timestamp: now
  } encrypted with session_key = K_s
  service: cifs/fileserver01.domain.local
```

🧠 This says:

> "Hey KDC, I have this valid TGT. Can I get a ticket to access \fileserver01?"

The Authenticator ensures freshness and confirms Alice knows the session key (K_s).

---

### ✅ Step 4: TGS-REP — KDC issues service ticket

🖥️ **KDC → Alice**

```text
TGS-REP:
  Encrypted part (with K_s):
    session_key_2 = K_s2
    ticket_lifetime = 10h
  Service Ticket:
    {
      client: alice
      session_key_2 = K_s2
      validity: 10h
      PAC: SID, groups
    } encrypted with service account hash (e.g., fileserver01$)

```

✅ Alice now has:

- A **Service Ticket** encrypted for the file server
    
- A **Session Key (K_s2)** to talk to it
    

---

### ✅ Step 5: AP-REQ — Alice connects to the file server

🧑 **Alice → fileserver01** (TCP/445, inside SMB or RPC)

```text
AP-REQ:
  ticket = {alice, K_s2, PAC}_enc_with_fileserver_key
  authenticator = {
    cname: alice
    timestamp: now
  } encrypted with K_s2
```

🧠 This says:

> "Here’s my service ticket. I’m Alice, and I just encrypted this with the session key inside the ticket — prove it."

📁 **The file server decrypts the ticket using its own password hash**, and checks the authenticator timestamp.

---

### ✅ Step 6: AP-REP (optional) — File server proves it’s legit

📁 **fileserver01 → Alice**
```text
AP-REP:
  {timestamp + 1} encrypted with K_s2
```

🧠 This says:

> "You’re talking to the real file server — here's your timestamp +1 as proof."

---

### ✅ Step 7: Access granted

📁 File server reads Alice’s PAC (Privilege Attribute Certificate) → sees:

- User SID
    
- Group memberships (Domain Users, Domain Admins, etc.)
    
Alice gets a **security token** locally on the server and now has access to the share.

✅ Authentication is complete — authorization happens using the PAC.