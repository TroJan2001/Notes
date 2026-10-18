# 🔹 What Is a Share?

- A **share** in SMB is just a **named entry point** that clients can connect to.
    
- Example: `\\HOST\SHARE`
    
    - If it’s a **file share** → it maps to a folder on disk.
        
    - If it’s **IPC$** → it maps to a namespace of **named pipes** instead of files.
        

👉 So `IPC$` isn’t “just a pipe” — it’s a **special share that exposes all the system’s pipes**.

---
# 🔹 Named Pipes Over IPC$

- Locally on Windows: named pipes live under `\\.\pipe\` (e.g., `\\.\pipe\lsarpc`).
    
- Over the network: SMB exposes them via `\\HOST\IPC$\pipe\...`.
    
- To SMB, these pipes **look like files inside the IPC$ share**, but instead of reading/writing file data, you’re sending messages into a pipe connected to a service.
    
Example flow:

1. Client connects to `\\HOST\IPC$`.
    
2. Opens `\pipe\lsarpc` (via SMB **Create File** request).
    
3. Behind that pipe, the **LSASS service** is waiting for RPC calls.
    
4. Client sends MSRPC packets through this pipe → LSASS processes them → replies go back via SMB.
    

👉 From SMB’s perspective, it’s just “reading/writing a file in IPC$.”  
👉 From Windows’ perspective, it’s “calling an API in LSASS remotely.”

---

# 🔹 What Are SAMR, LSA, Spooler ... etc?

These are **RPC interfaces**, each exposed via a named pipe in IPC$:

| Pipe             | Service                             | Purpose                                                          |
| ---------------- | ----------------------------------- | ---------------------------------------------------------------- |
| `\pipe\samr`     | **Security Account Manager Remote** | Manage users & groups (list domain users, reset passwords, etc.) |
| `\pipe\lsarpc`   | **Local Security Authority RPC**    | Security policy, trust info, SID lookups                         |
| `\pipe\spoolss`  | **Print Spooler Service**           | Manage printers (PrintNightmare vuln lives here)                 |
| `\pipe\netlogon` | **Netlogon Service**                | Domain logons, replication support                               |
| `\pipe\wkssvc`   | **Workstation Service**             | Info about logged-on users, domain/workgroup                     |

All of these are implemented as **MSRPC endpoints**, but accessed over SMB → IPC$ → named pipe.

---

# 🔹 Why Does IPC$ Look Like a “Protocol”?

Because SMB treats everything (files, printers, pipes) as “objects in a share.”

- For files: read/write disk.
    
- For printers: spool print jobs.
    
- For pipes: forward messages to a waiting service process.
    

So when Wireshark or tools show “SMB → IPC$,” it looks like a **protocol** because you’re really riding SMB → Named Pipes → MSRPC.

---

# 🔹 SMB Integration Summary

- **File/Printer shares** → `\\HOST\share` → normal file/print access.
    
- **Admin shares** → `\\HOST\C$`, `\\HOST\ADMIN$` → hidden shares, admin-only.
    
- **IPC$ share** → `\\HOST\IPC$` → special share exposing named pipes like `\pipe\samr`, `\pipe\lsarpc`.
    
    - These pipes are **MSRPC transports**.
        
    - They connect you to deep Windows services (SAMR, LSA, Netlogon, Spooler).
        

👉 So:

- A **share** is just the SMB entry point.
    
- **IPC$** is a share dedicated to pipes.
    
- Pipes carry **MSRPC** traffic.
    
- MSRPC is how Windows exposes internal services across the network.
    

---
# 🔹 Default SMB Shares in Windows

Windows automatically creates some hidden administrative shares. Hidden means they end with a `$` and don’t show up in Explorer, but they exist unless explicitly disabled.

|Share|Purpose|
|---|---|
|**C$**|Root of the C: drive (same for D$, E$, etc. for each local drive)|
|**ADMIN$**|Points to `%SystemRoot%` (usually `C:\Windows`), used for remote admin tasks|
|**IPC$**|Inter-Process Communication share, used for **named pipes** (SAMR, LSA, Spooler, etc.)|
|**PRINT$**|Exposes printer driver files (for clients to download drivers)|
|**NETLOGON**|(On Domain Controllers) Contains logon scripts and policies|
|**SYSVOL**|(On Domain Controllers) Stores domain-wide public files, Group Policy, scripts|

---

# 🔹 Default Access Permissions

### 1. **C$, D$, E$ (Drive Shares)**

- **Default Access**:
    
    - Only **Administrators** group (local or domain).
        
    - **No access** for normal users.
        
- **Use Case**: Remote file system management by admins.
    

---

### 2. **ADMIN$**

- **Default Access**:
    
    - Only **Administrators** group.
        
- **Use Case**:
    
    - Remote admin tools (e.g., copying files into `%SystemRoot%`, running updates, PsExec uses this).
        

---

### 3. **IPC$**

- **Default Access**:
    
    - Any authenticated user can connect.
        
    - **Anonymous access** was allowed by default in very old Windows versions (→ Null Session vulnerabilities).
        
- **Use Case**:
    
    - Named pipe access (`\pipe\samr`, `\pipe\lsarpc`, `\pipe\netlogon`).
        
    - Remote administration, RPC calls, AD enumeration.
        

👉 This is why IPC$ is such a big recon surface: even low-priv users can open it and query things like user lists.

---

### 4. **PRINT$**

- **Default Access**:
    
    - Authenticated users → read (to fetch drivers).
        
    - Admins → full access.
        
- **Use Case**:
    
    - Printer driver distribution.
        
    - Unfortunately, this has been abused in attacks (e.g., **PrintNightmare**).
        

---

### 5. **NETLOGON** (DC Only)

- **Default Access**:
    
    - Authenticated domain users → read access.
        
    - Domain Admins → full access.
        
- **Use Case**:
    
    - Logon scripts, policies.
        
- **Abuse**:
    
    - Can leak plaintext passwords in misconfigured logon scripts.
        

---

### 6. **SYSVOL** (DC Only)

- **Default Access**:
    
    - Authenticated domain users → read access.
        
    - Domain Admins → full access.
        
- **Use Case**:
    
    - Group Policy distribution.
        
- **Abuse**:
    
    - Attackers harvest GPO scripts for creds, secrets.