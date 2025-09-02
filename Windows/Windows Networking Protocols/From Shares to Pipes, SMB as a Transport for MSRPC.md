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
