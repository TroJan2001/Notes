# 🔹 What is SMB?

- **SMB = Server Message Block**
    
- Microsoft’s network file sharing and IPC (inter-process communication) protocol.
    
- Lets clients **read/write files, access printers, or talk to named pipes** on a remote machine.
    
- Equivalent in concept to **NFS** on Unix, but much more integrated with Windows (authentication, Active Directory, RPC).
    

---

# 🔹 How SMB Works

1. **Connection**
    
    - Client connects to the server on **TCP 445** (or legacy 139 via NetBIOS).
        
    - Negotiates SMB dialect (SMBv1, 2.x, 3.x).
        
2. **Authentication**
    
    - Client authenticates with **NTLM** or **Kerberos** (in AD domains).
        
3. **Tree Connect**
    
    - Client requests access to a specific **share**:
        
        - `\\HOST\C$` (admin share for C drive)
            
        - `\\HOST\IPC$` (named pipes, RPC)
            
        - `\\HOST\SHARE` (user-defined share).
            
4. **Operations**
    
    - Once connected, client can read/write files, print, or use named pipes for RPC.
        

---

# 🔹 SMB Versions

|Version|Year|Notes|
|---|---|---|
|SMBv1|1980s|Very chatty, weak security. Vulnerable to **EternalBlue** (MS17-010). Deprecated.|
|SMBv2|2006|Faster, less chattiness, larger reads/writes.|
|SMBv3|2012+|Adds encryption, signing, compression, multichannel. Current standard.|
|SMB 3.1.1|2016+|Stronger crypto (AES-GCM/CCM), pre-auth integrity. Default in Win10/Server 2016+.|

---

# 🔹 SMB Shares

- **File/Printer shares** → `\\HOST\share`
    
- **Administrative shares** → hidden, end with `$` (C$, ADMIN$, IPC$).
    
- **IPC$** = _special share for Inter-Process Communication_
    
    - Hosts **named pipes** (e.g., `\pipe\samr`, `\pipe\lsarpc`)
        
    - Used by MSRPC to reach services like SAMR, LSA, Spooler.
        

---

# 🔹 SMB vs NFS

|Feature|SMB|NFS|
|---|---|---|
|Origin|Microsoft/IBM|Sun Microsystems (Unix)|
|Default Port|TCP 445 (or 139 legacy)|TCP/UDP 2049 (via RPC)|
|Auth|NTLM / Kerberos (AD integrated)|Host-based, or Kerberos (NFSv4)|
|Extra Features|Named pipes, RPC, DFS, AD replication|Mostly just file access|
|Typical Use Case|Windows domains, file/print, AD|Unix/Linux servers, HPC clusters|

---

# 🔹 Security Relevance

- **SMBv1 must be disabled** (WannaCry, NotPetya).
    
- SMB authentication is a common target:
    
    - **Pass-the-Hash** (reuse NTLM hashes).
        
    - **NTLM relay attacks** (relay to another SMB service).
        
- SMB used for **lateral movement**:
    
    - `\\TARGET\ADMIN$` access → remote file copy.
        
    - `\\TARGET\IPC$` pipes → MSRPC calls (enumerate users, policies).
        

---

# 🔹 Example Recon / Attack Flow

1. **Discover SMB**:
    
    `nmap -p445 --script smb-os-discovery,smb-enum-shares 10.0.0.10`
    
2. **Enumerate shares**:
    
    `smbmap -H 10.0.0.10 -u guest`
    
3. **Query users via RPC** (over IPC$):
    
    `rpcclient -U "" -N 10.0.0.10 > enumdomusers`
    
4. **Move laterally**:
    
    - Copy tools to `\\TARGET\C$\Temp\`
        
    - Execute via `psexec`, `wmiexec`, or `smbexec`.