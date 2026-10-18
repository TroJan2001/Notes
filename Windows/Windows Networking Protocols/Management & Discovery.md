---
title: "Management & Discovery"
created: 2026-03-11
type: concept
tags: [concept, network, protocols, windows]
---

# 🗂 Management & Discovery

## 1. WinRM (Windows Remote Management)

- **Ports:**
    
    - TCP 5985 (HTTP)
        
    - TCP 5986 (HTTPS with TLS)
        
- **Protocol:** WS-Management (SOAP over HTTP/S)
    
- **Purpose:** Standards-based remote administration (replacement for WMI/DCOM over RPC in many cases).
    
- **Usage Examples:**
    
    - Powershell Remoting: `Enter-PSSession -ComputerName DC01`
        
    - Group Policy uses it for remote querying.
        
- **Flow:**
    
```text
Client → SOAP/XML request (WS-Management)
       → over HTTP (5985) or HTTPS (5986)
       → received by WinRM service
       → parsed and mapped to local providers (e.g., WMI/DCOM, PowerShell)
         [Note: no RPC/DCOM on the wire; only SOAP/HTTP/S]
       → provider executes request locally
       → result mapped back into SOAP/XML
       → returned over HTTP/S to client
```
    
- **Security Notes:**
    
    - Auth can be Kerberos (default in domain) or NTLM/Basic.
        
    - If HTTPS is not enforced, creds may be sniffed/relayed.
        
    - Often abused in lateral movement (`evil-winrm` tool).
        

---

## 2. WMI (Windows Management Instrumentation)

- **Transport:** WMI uses **DCOM**, which rides on **MSRPC** (TCP 135 + dynamic high ports, or SMB named pipes).
    
- **Purpose:** System management framework (query OS info, processes, services, etc.).
    
- **Usage Examples:**
    
    - Query processes: `wmic process list`
        
    - Remote execution: `wmic /node:Target process call create "cmd.exe /c whoami"`
        
- **Flow:**
    
```text
Client → WMI API call (CIM query or method)
       → marshalled into COM/DCOM call
       → DCOM serializes request into MSRPC
       → RPC transport opens via Endpoint Mapper (135/tcp)
       → dynamic high TCP port assigned
       → request delivered to WMI provider on target
       → provider executes (returns CIM objects)
       → CIM objects → DCOM marshals response → RPC transport → back to client

#Or

Client → WMI API call
       → COM/DCOM marshalling
       → RPC carried over SMB (445/tcp)
       → named pipe (e.g., \pipe\winreg)
       → WMI provider executes
       → response marshalled back over SMB pipe to client

```
    
- **Security Notes:**
    
    - Requires admin rights on the target.
        
    - Common pentest lateral move vector (`wmiexec.py`, Impacket).
        
    - Can be secured by limiting DCOM or requiring WinRM instead.
        

---

## 3. WSD / Function Discovery / PnP-X

- **Ports:**
    
    - UDP/TCP 3702 → WS-Discovery (SOAP over UDP multicast).
        
    - Uses HTTP/SOAP envelopes for messages.
        
- **Purpose:** Service discovery in local networks (modern alternative to LLMNR/NBT).
    
    - Used for discovering printers, scanners, IoT devices, and Windows services.
        
    - Function Discovery (FDResPub) and Plug and Play Extensions (PnP-X) ride on WSD.
        
- **Flow:**
    
```text
Client → WS-Discovery Probe (SOAP/XML message)
       → over UDP multicast (3702/udp)
       → all devices on subnet receive query
Devices with matching service → respond with Hello/ProbeMatch
       → SOAP/XML response over UDP (or TCP 3702 if required)
       → response contains metadata (service type, endpoint address)
       → client uses provided IP/port to connect (usually via HTTP/SOAP)
```
    
- **Security Notes:**
    
    - Multicast → can be spoofed, enabling device impersonation.
        
    - Attackers can poison WSD discovery to fake printers/scanners.
        
    - Often disabled in hardened enterprise networks.

# 📍 Where WinRM and WMI Fit

## 🟦 WMI (Windows Management Instrumentation)

- **What it is:**  
    A management framework that exposes **system info, processes, services, hardware data** via the CIM (Common Information Model).
    
- **How it communicates remotely:**
    
    - **DCOM over RPC**
        
        - Client binds to `RPCSS` (135/tcp) → gets a dynamic port.
            
        - RPC calls are serialized COM method calls.
            
        - WMI returns CIM objects.
            
    - Sometimes **RPC over SMB pipes** (`\pipe\atsvc`, `\pipe\winreg`, etc.) if TCP is blocked.
        
- **Summary:**  
    WMI = **management API**  
    → implemented as **COM/DCOM objects**  
    → carried by **RPC**  
    → over **TCP or SMB**
    

---

## 🟦 WinRM (Windows Remote Management)

- **What it is:**  
    Microsoft’s **standards-based remote management** service. Implements **WS-Management** (SOAP over HTTP/S).  
    Basically: a “web service front-end” to Windows management (including WMI).
    
- **How it communicates remotely:**
    
    - **HTTP 5985** or **HTTPS 5986**
        
    - Messages are **SOAP/XML envelopes** (no RPC).
        
    - Server maps SOAP calls to local APIs (including WMI providers).
        
- **Summary:**  
    WinRM = **protocol wrapper** (WS-Man over HTTP/S)  
    → talks SOAP/XML on the wire  
    → converts into WMI/DCOM or other mgmt APIs internally
    

---

# 🔗 Putting It Together (Visual)

`[Management Layer]  ├─ WMI (mgmt API)    │    └─ implemented via COM/DCOM    │          └─ RPC (TCP 135 + dynamic OR SMB pipes)  │  └─ WinRM (mgmt API over network)         └─ WS-Management (SOAP/XML)              └─ HTTP (5985) or HTTPS (5986)            └─ internally maps to WMI/DCOM providers`

---

# 🧑‍💻 Attacker View

- **WMI (DCOM/RPC)**
    
    - Used in lateral movement: `wmiexec.py`, PowerShell `Get-WmiObject -ComputerName`.
        
    - Requires **TCP 135 + high ports** (or SMB).
        
    - Auth via NTLM/Kerberos.
        
- **WinRM (SOAP/HTTP)**
    
    - Used by `evil-winrm`, PowerShell Remoting (`Enter-PSSession`).
        
    - Only needs **5985/5986 open** → firewall-friendly.
        
    - Auth via NTLM/Kerberos/Basic.
        

---

👉 So:

- **WMI = COM/DCOM-based, RPC transport**.
    
- **WinRM = web service, SOAP transport, but calls into WMI under the hood**.