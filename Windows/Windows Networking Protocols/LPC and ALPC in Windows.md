
## 1. What is LPC?

- **LPC = Local Procedure Call**.
    
- Kernel mechanism in Windows NT for **fast, local-only IPC**.
    
- Lets user-mode processes call system services as if they were local procedures.
    
- Structured like RPC but **cannot leave the machine**.
    

👉 Think of LPC as **RPC inside one computer**.

---

## 2. What is ALPC?

- **ALPC = Advanced Local Procedure Call**.
    
- Introduced in **Windows Vista** to replace LPC.
    
- Provides:
    
    - Higher performance (uses shared memory channels).
        
    - Flexible message passing (handles large/complex objects).
        
    - Security descriptors for isolation.
        
- Still **local-only** (not networked).
    

---

## 3. Where It’s Used

- Communication between **user-mode DLLs** (e.g., `ntdll.dll`) and the **Windows kernel**.
    
- Example:
    
    - App calls `CreateFile()` → API marshals request into an ALPC message.
        
    - Message sent to kernel subsystem (I/O Manager).
        
    - Kernel executes, returns via ALPC.
        
- Windows services use ALPC to talk to core processes (`lsass.exe`, `csrss.exe`, etc.).
    
---

## 4. Comparison: LPC/ALPC vs SMB/RPC

|Feature|LPC / ALPC (Local)|SMB / MSRPC (Remote)|
|---|---|---|
|Scope|Local-only (same machine)|Remote, cross-machine|
|Transport|Kernel message passing, shared memory|TCP, SMB, HTTP, Named Pipes|
|Use Case|User ↔ Kernel, system services|File sharing, AD, domain services|
|Security|Kernel ACLs on ALPC ports|NTLM / Kerberos authentication|

---

## 5. Security Relevance

- ALPC interfaces can be abused for **local privilege escalation** if insecure.
    
- Past Windows exploits involved crafted ALPC messages to privileged services (e.g., Print Spooler bugs).
    
- Tools: Sysinternals **WinObj** or **Process Explorer** can reveal ALPC ports.
    

---
