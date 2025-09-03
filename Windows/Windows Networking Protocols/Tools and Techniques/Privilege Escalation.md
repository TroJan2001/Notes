## Windows Local Privilege Escalation

---
### JuicyPotato / RoguePotato / PrintSpoofer

**Flow:**

- **You’re on a machine already** (maybe via RDP, reverse shell, or a service account).
    
    - Example: you have `NT AUTHORITY\LOCAL SERVICE` or `IIS APPPOOL\WebApp`.
- That account often has a right called **SeImpersonatePrivilege**.
    
    - Windows gave this to service accounts so they can act “on behalf of” users.
- The exploit (JuicyPotato, PrintSpoofer, etc.) **coerces a privileged Windows service** (like the Print Spooler or RPCSS) to connect back to you.
    
- When that service connects, Windows includes a **SYSTEM token** (an identity proof).
    
- The exploit grabs that token and tells Windows:
    
    - “Hey, run my process as this SYSTEM guy instead.”
    
- Windows says okay → your shell is now **NT AUTHORITY\SYSTEM**.M**.
    
- **Requires:** Local code exec + SeImpersonatePrivilege.
    
- **Impact:** SYSTEM on that box.
    
- **Example Commands:**

```bash
PrintSpoofer64.exe -c "cmd.exe"
JuicyPotato.exe -t * -p cmd.exe -l 1337
RoguePotato.exe -r 10.0.0.1 -e "cmd.exe"
```

- **Transport Stack:** Local RPC/COM → Named Pipes.

---

### PrintNightmare (CVE-2021-34527)

PrintNightmare is a **Windows Print Spooler vulnerability** that made big news in 2021.

- The **Print Spooler** is the Windows service that manages printing jobs for your computer.
    
- Because the Spooler runs with **SYSTEM** privileges, if an attacker can trick it into loading their code, they instantly become SYSTEM.
    
- The bug let attackers (both local and sometimes remote) abuse the Spooler to **install a malicious printer driver or DLL**.

**Flow:**

- **Attacker connects to the Print Spooler service**
    
    - Either locally (on their own machine) or remotely (to another host if it has Spooler running).
        
- **Abuse printer driver installation**
    
    - Spooler allows users with certain rights to add printer drivers.
        
    - The vulnerability failed to properly check permissions and paths.
        
- **Upload malicious DLL disguised as a printer driver**
    
    - Attacker tells the Spooler: “Hey, load this driver I made.”
        
    - The “driver” is really a payload.
        
- **Spooler loads the attacker’s DLL with SYSTEM privileges**
    
    - Because Spooler is SYSTEM, your code now runs as SYSTEM.
        
- **SYSTEM shell obtained**
    
    - From here you can dump credentials, pivot, or move laterally.
    
- **Requires:** Spooler running + unpatched system.
    
- **Impact:** SYSTEM locally or remote code exec if targeting remote Spooler.
    
- **Example Commands:**

```bash
# Example exploit PoC
python CVE-2021-34527.py -t 10.0.0.5 -c "cmd.exe"

# Or Metasploit module
use exploit/windows/printnightmare/printnightmare
set RHOSTS 10.0.0.5
```    

- **Transport Stack:** MSRPC over SMB (Spooler).

---
## Active Directory / Domain Escalation

---
**Netlogon** is a **Windows service** (listening over RPC) that manages the **secure channel** between:

- a **domain-joined computer** (the client)
    
- and a **Domain Controller** (the DC).
    

It’s not “Kerberos vs NTLM” — those are user authentication protocols.  
Netlogon is more like the **trust tunnel** that computers use to talk to their DC.
### ZeroLogon (CVE-2020-1472)

ZeroLogon is a vulnerability in the **Netlogon Remote Protocol (MS-NRPC)**, which is used by domain-joined machines to securely talk to Domain Controllers (DCs).

- It was discovered in 2020 and nicknamed _“ZeroLogon”_ because the exploit worked by sending **all-zero values** in the authentication process.
    
- If successful, it let an attacker **reset the machine account password** of a Domain Controller… to a blank password.
    
- That means they could **pretend to be the DC** itself, and once you’re a DC, you’re basically Domain Admin.

**Flow:**

- **Attacker connects to Netlogon service on the Domain Controller**
    
    - This service normally helps domain machines set up secure channels.
        
    - Runs over RPC.
        
- **Exploit the crypto flaw**
    
    - The bug was in how Netlogon handled an AES-based authentication step.
        
    - By sending special messages filled with **zeros**, the attacker had a 1-in-256 chance of bypassing authentication.
        
    - Just retrying multiple times guaranteed success.
        
- **Reset the DC machine account password**
    
    - Once authenticated, attacker sends a “Set machine account password” request… setting the password to all zeros.
        
- **Take over the Domain Controller**
    
    - Now attacker knows the DC’s account password (zero).
        
    - They can authenticate as the DC itself.
        
- **Dump or modify everything**
    
    - Use DC privileges to dump all domain secrets (DCSync, krbtgt hash).
        
    - Add new admins, change policies, full forest compromise.

- **Requires:** Network access to DC Netlogon.
    
- **Impact:** Full DC takeover → Domain Admin.
    
- **Example Commands:**

```bash
# PoC test script
zerologon_tester.py DC01 10.0.0.1

# Full exploit (sets DC account password to 0’s)
python cve-2020-1472-exploit.py DC01 10.0.0.1
```

After resetting the DC account password:

- Use **secretsdump.py** with the new blank password to DCSync and dump all hashes.

```bash
secretsdump.py -just-dc -no-pass domain/DC01\$@10.0.0.1
```
- **Transport Stack:** Netlogon (MS-NRPC) over RPC.

---

### NoPac (CVE-2021-42278/42287)

“NoPac” is a **Kerberos + LDAP attack chain** discovered in 2021.  
It’s actually **two vulnerabilities combined**:

1. **CVE-2021-42278** – allows **sAMAccountName spoofing** (you can rename a computer account to look like a Domain Controller).
    
2. **CVE-2021-42287** – Kerberos doesn’t properly verify who asked for a ticket when issuing TGTs.

When chained, these bugs let a **low-privileged domain user** trick the DC into giving them a **TGT as a Domain Controller**.  

**Flow:**

1. **Start with low-priv user**
    
    - Attacker has a normal domain account (`user@domain.local`).
        
2. **Create or control a computer account**
    
    - In AD, normal users by default can create up to 10 machine accounts (unless restricted).
        
    - Example: attacker creates `FAKEPC$`.
        
3. **Rename computer account (sAMAccountName spoofing)**
    
    - Using LDAP, attacker renames `FAKEPC$` → `DC01` (the same name as the real Domain Controller).
        
    - Now there are _two objects_ with the name `DC01` in AD.
        
4. **Request a TGT for this “fake DC”**
    
    - Attacker asks the KDC (Kerberos DC service) for a TGT for `DC01`.
        
    - Because of the bug, the DC doesn’t distinguish the spoofed account from the real DC account.
        
5. **KDC issues a TGT for the actual DC account**
    
    - Attacker now has a valid **Domain Controller TGT**.
        
6. **Escalate to Domain Admin**
    
    - With a DC’s Kerberos identity, attacker can request service tickets for anything.
        
    - They can perform **DCSync** to dump the `krbtgt` hash, or impersonate DA directly.
    
- **Example Commands:**

```bash
# Impacket noPac PoC
python noPac.py -dc-ip 10.0.0.1 -dc-name DC01 -u user -p 'Password123!' -domain domain.local

# Rubeus equivalent (manipulating sAMAccountName + requesting TGT)
Rubeus asktgt /user:DC01$ /password:FakePass /dc:DC01.domain.local
```

- **Transport Stack:** Kerberos + LDAP.

---

### DCSync

**DCSync** is not a software bug, it’s a **feature abuse**.  
It uses the **Directory Replication Service (DRSUAPI)** RPC interface to ask a Domain Controller to replicate password data.

- Normally: DCs replicate account changes with each other.
    
- Attack: If you trick a DC into believing you are another DC (or an account with replication rights), it will happily give you **password hashes for any user** in the domain.

**Flow:**

- **Attacker has high AD privileges**
    
    - Needs Domain Admin, Enterprise Admin, or just the special right:
        
        - `Replicating Directory Changes`
            
        - `Replicating Directory Changes All`
            
        - `Replicating Directory Changes In Filtered Set`.
            
- **Uses replication API (DRSUAPI)**
    
    - Through RPC over SMB (TCP 445), attacker makes replication requests.
        
- **Ask for specific user secrets**
    
    - For example: `Administrator`, `krbtgt`, or _all accounts_.
        
- **Domain Controller responds**
    
    - Returns NTLM hashes, Kerberos keys, AES keys.
        
- **Attacker now owns the domain**
    
    - With `krbtgt` hash → forge Golden Tickets.
        
    - With DA hashes → lateral move.
        
    - With user hashes → offline cracking.
    
- **Example Commands:**

```bash
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt
mimikatz # lsadump::dcsync /domain:domain.local /user:Administrator

#Or
secretsdump.py -just-dc domain.local/Administrator:'Password123!'@dc01.domain.local
```

- **Transport Stack:** MSRPC (DRSUAPI) over SMB.

---

### DCShadow

**Flow:**

1. Attacker registers rogue DC.
    
2. Pushes **malicious AD changes** that appear as replication.
    
3. Modifies ACLs, groups, objects stealthily.
    

- **Requires:** DA/EA to register DC.
    
- **Impact:** Persistence via stealthy AD changes.
    
- **Example Commands:**

```bash
mimikatz # lsadump::dcshadow /object:CN=User1,CN=Users,DC=domain,DC=local /attribute:adminCount /value:1

#Or

mimikatz # lsadump::dcshadow /object:CN=attacker,CN=Users,DC=domain,DC=local /attribute:memberOf /value:"CN=Domain Admins,CN=Users,DC=domain,DC=local"
```

- **Transport Stack:** AD replication (MSRPC).

---

### Delegation Abuse (Unconstrained, Constrained, RBCD)

- Delegation = allowing a service (like IIS or SQL) to impersonate users when talking to another service.
    
- Windows supports three forms:
    
    - **Unconstrained Delegation** → service can impersonate _anyone_ to _any service_.
        
    - **Constrained Delegation** → service can impersonate certain users, but only to _specific services_.
        
    - **Resource-Based Constrained Delegation (RBCD)** → newer feature where the _target resource_ (not admins) controls who can impersonate to it.

**Flow:**

1. Attacker controls account/computer allowed to delegate.
    
2. Abuse Kerberos S4U2Self / S4U2Proxy to impersonate victim.
    
3. Obtain service tickets to high-value resources.

- **Requires:** Control of delegatable object, or write on computer (for RBCD).
    
- **Impact:** Lateral move to DA paths.
    
- **Example Commands:**

```bash
Rubeus s4u /user:svc_deleg /impersonateuser:Administrator /rc4:<hash>
```

- **Transport Stack:** Kerberos.

---

### ACL Abuse

- In AD, **every object (user, group, computer, GPO)** has an **ACL (Access Control List)**.
    
- If attacker has write access to an object’s ACL, they can silently escalate.

**Flow:**
- Attacker gains write access to a target object (maybe via misconfigured delegation or inheritance).
    
- Modify ACL to grant themselves powerful rights:
    
    - **ResetPassword** → set a new password for an account.
        
    - **AddMembers** → put themselves into an admin group.
        
    - **WriteDACL** → give themselves full control.
        
- Use these new rights to escalate.

- **Requires:** Any AD write rights.
    
- **Impact:** Take over users, groups, or policies.
    
- **Transport Stack:** LDAP (389/636).

---

### ADCS Misconfigurations (ESC1–ESC8)

- **AD Certificate Services (ADCS)** issues certs for Kerberos/PKI.
    
- Weak certificate templates can let attackers request certs that impersonate others (like a DA).
    
- SpecterOps mapped common misconfigs as **ESC1 → ESC8**.

**Flow:**

- Attacker finds a misconfigured template (e.g., one that lets “Authenticated Users” request certs for logon).
    
- Request a cert for a high-privileged user (like Administrator).
    
- Use cert with PKINIT (Kerberos pre-auth with smartcard logon).
    
- Log in as that user without needing their password.

- **Requires:** ADCS deployed with weak templates or CA key exposed.
    
- **Impact:** Full domain compromise, “Golden Cert” persistence.
    
- **Example Commands:**

```bash
certipy req -u lowuser -p P@ss -target ca.domain.local -template ESC1
```    

- **Transport Stack:** HTTP certsrv, RPC to CA, Kerberos/X.509.

---
### NTLM Relay via Coercion (PetitPotam / PrinterBug / DFSCoerce)

- NTLM relay = force a machine to authenticate to you, then relay those creds to another service.
    
- **Coercion** = using Windows RPC tricks to make a DC connect out (e.g., via EFSRPC, Print Spooler, DFSNM).

**Flow:**

- Attacker coerces a DC or machine → “Please authenticate to me.”
    
    - Example: PetitPotam uses **EFSRPC**.
        
- DC sends NTLM authentication to attacker.
    
- Attacker relays NTLM to a service that accepts it (like LDAP or ADCS HTTP).
    
- Relay succeeds → attacker can request cert as DC or make LDAP changes.
    

- **Requires:** Ability to coerce + target accepting NTLM.
    
- **Impact:** DC cert issuance → DA.
    
- **Example Commands:**

```bash
petitpotam.py -d domain.local -u user -p pass 10.0.0.5
```  
  
- **Transport Stack:** RPC coercion (EFSRPC/RPRN/DFSNM) + NTLM relay to LDAP/HTTP.