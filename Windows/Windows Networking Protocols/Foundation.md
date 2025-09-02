This section builds on **Operating System IPC** (shared memory, pipes, queues, sockets) and explains how Microsoft layered those concepts into **network-facing services**. The result is a hierarchy that moves from local IPC → remote IPC → enterprise services like SMB, RPC, and Active Directory components.

---

## 1. Layered View

```text
[OS IPC]
 ├─ Shared Memory
 └─ Message Passing
     ├─ Pipes
     ├─ Queues
     └─ Sockets

[Windows Remote IPC Stack]  
├── Name Resolution  
│ • NBT-NS (137/udp)  
│ • LLMNR (5355/udp)  
│ • mDNS, WSD (modern discovery)  
├── Transport  
│ • NetBIOS-SSN (139/tcp)  
│ • SMB (445/tcp)  
│ • Named Pipes (IPC$ share in SMB)  
├── RPC Framework
│ • MSRPC (135/tcp + dynamic ports)  
│ • RPC over SMB, TCP, HTTP  
│ • Endpoint Mapper (EPM)  
│ • LPC/ALPC (local-only, kernel)  
├── Authentication & Identity  
│ • NTLM (challenge–response)  
│ • Kerberos (ticket-based, 88/tcp/udp)  
│ • LDAP (389/636, AD directory queries)  
├── Management & Discovery  
│ • WinRM (5985/5986, SOAP/HTTP[S])  
│ • WMI (RPC-based, 135 + high ports)  
│ • WSD / Function Discovery / PnP-X  
├── File Sharing Protocols  
│ • SMB (native Windows file/print/IPC)  
│ • NFS (cross-platform, RPC-based)  
├── Services 
│ • SMB (file/print/IPC)  
│ • RDP (3389/tcp, remote desktop)
│ • RPC-based services (SAMR, LSA, WMI, DCOM, Spooler) 
└──
```

---
## 2. Ordering of Protocols

1. **Name Resolution**
    
    - NetBIOS Name Service (137/udp)
        
    - LLMNR (5355/udp)
        
    - mDNS, WSD (modern discovery mechanisms)
        
2. **Transport**
    
    - NetBIOS Session Service (139/tcp)
        
    - SMB over TCP (445/tcp)
        
    - Named Pipes (`IPC$`)
        
3. **RPC Framework**
    
    - MSRPC (135/tcp + dynamic ports)
        
    - RPC over SMB, TCP, or HTTP
        
    - Endpoint Mapper (EPM)
        
    - LPC/ALPC (local IPC)
        
4. **Authentication & Identity**
    
    - NTLM (challenge–response, used by SMB/RPC/RDP)
        
    - Kerberos (ticket-based, default in AD domains)
        
    - LDAP (directory queries, integrates with Kerberos/NTLM)
        
5. **Management & Discovery**
    
    - WinRM (HTTP 5985 / HTTPS 5986)
        
    - WMI (leveraging RPC)
        
    - WSD / Function Discovery (devices)
        
6. **File Sharing Protocols**
    
    - SMB (native, core Windows sharing)
        
    - NFS (cross-platform, RPC-based)
        
7. **Service Protocols**
    
    - SMB (file/print/IPC)
        
    - RDP (remote desktop, clipboard/device redirection)
        
    - RPC-based services (SAMR, LSA, WMI, DCOM, Spooler)

---

## 3. How They Connect

- **Local IPC → Remote IPC**
    
    - Pipes, queues, and sockets form the primitives.
        
    - Windows exposes **Named Pipes** over SMB (`\\HOST\IPC$\pipe\...`) so remote processes can use them as if local.
        
    - RPC can run over these pipes (`ncacn_np`), TCP (`ncacn_ip_tcp`), or HTTP (`ncacn_http`).
        
- **Name Resolution → Transport**
    
    - NBT-NS, LLMNR, mDNS, or WSD resolve hostnames when DNS fails.
        
    - Once resolved, communication proceeds over NetBIOS-SSN (139) or SMB (445).
        
- **SMB → Named Pipes → MSRPC**
    
    - SMB provides the **IPC$ share** as a container for inter-process channels.
        
    - Named Pipes inside IPC$ (e.g., `\pipe\samr`, `\pipe\lsarpc`) carry MSRPC traffic.
        
    - Endpoint Mapper on port 135 maps interface UUIDs to their pipe or port.
        
- **Authentication (NTLM and Kerberos)**
    
    - **NTLM**:
        
        - Challenge–response protocol.
            
        - Common fallback when Kerberos cannot be used (workgroups, legacy systems, cross-forest without trust).
            
        - Used heavily by SMB, RPC, and RDP during initial authentication.
            
    - **Kerberos**:
        
        - Preferred in Active Directory domains.
            
        - Ticket-based protocol (KDC over port 88).
            
        - Used by LDAP, SMB, RPC, RDP once domain-joined.
            
- **MSRPC → Core Windows Services**
    
    - RPC interfaces expose services like:
        
        - **SAMR** (user/group management)
            
        - **LSA** (authentication policy, ties into NTLM/Kerberos)
            
        - **WMI/DCOM** (system management, COM objects)
            
        - **Spooler** (printer services)
            
    - These RPC interfaces are fundamental for **domain operations** and AD administration.
        
- **Management Layers (WinRM / WMI)**
    
    - WinRM uses SOAP over HTTP(S) (5985/5986) with **Kerberos or NTLM** authentication.
        
    - WMI often uses RPC under the hood (via DCOM).
        
    - Both are heavily used in domain administration and are common lateral movement channels.
        
- **File Sharing Protocols**
    
    - SMB is the native mechanism for file/print sharing and IPC.
        
    - Authentication typically via **NTLM** (legacy/workgroup) or **Kerberos** (domain).
        
    - NFS is optional for Unix/Windows interoperability, built on top of RPC.
        
- **Service Protocols**
    
    - RDP (3389) provides graphical remote access.
        
    - Relies on **NTLM or Kerberos** for authentication (depending on environment).
        
    - May use RPC for features like clipboard/device redirection.
        
- **Directory & Authentication (AD context)**
    
    - **Kerberos (88)** and **LDAP (389/636)** are the **identity plane** for Active Directory.
        
    - NTLM still exists for backward compatibility and certain cross-domain scenarios.
        
    - AD replication uses **RPC** over SMB (e.g., DRSUAPI interface).
