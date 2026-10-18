---
title: "Windows Print Spooler Service"
created: 2026-03-11
type: concept
tags: [concept, network, protocols, windows]
---

## 1. Overview

- **Service Name:** Print Spooler (`spoolsv.exe`)
    
- **Purpose:** Manages print jobs in Windows by queuing, scheduling, and sending them to printers.
    
- **Concept:** Acts as a buffer so applications don’t have to wait while printers process jobs.

---

## 2. Functions

- Accepts print jobs from applications.
    
- Queues jobs in `C:\Windows\System32\spool\PRINTERS`.
    
- Manages printer drivers and settings.
    
- Handles local printers (USB, LPT) and network printers (SMB, IPP, RPC).
    
- Provides APIs for applications and administrators (pause, cancel, configure, list jobs).

---

## 3. Interfaces

### Local Interfaces

- Uses **ALPC (Advanced Local Procedure Call)** for fast, kernel-level IPC.
    
- Accepts API calls like `StartDocPrinter()`, `AddPrinter()`, etc.

### Remote Interfaces

- Exposes an **MSRPC interface** via the named pipe `\\pipe\\spoolss`.
    
- Accessible over SMB through the **IPC$ share**: `\\HOST\IPC$\pipe\spoolss`.
    
- Remote functions:
    
    - Enumerate printers
        
    - Install/remove drivers
        
    - Submit/cancel jobs
        
    - Configure printer shares
        

---

## 4. Security Impact

- **Runs as Local System** → exploitation grants SYSTEM privileges.
    
- **Exposed remotely** → available by default on most Windows systems.
    
- **Historic vulnerabilities:**
    
    - **PrintNightmare (CVE-2021-34527):** Remote Code Execution & [[Privilege Escalation]].
        
    - **MS08-070:** Buffer overflow in spooler RPC.
        
    - **NTLM relay/coercion attacks:** Spooler can be tricked into authenticating to attacker’s host.
        

---

## 5. In Context of IPC

- **Locally:** Uses ALPC for communication between apps, drivers, and kernel.
    
- **Remotely:** Uses MSRPC over SMB (via IPC$ and `spoolss` pipe).
    

👉 The Print Spooler is a key example of a Windows service exposed through **both ALPC (local)** and **MSRPC over SMB (remote)**.

---
