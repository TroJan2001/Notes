## 1. NetBIOS Session Service (NetBIOS-SSN, **139/tcp**)

- **Legacy role**: Before SMB ran directly over TCP (445), it used the **NetBIOS API**.
    
    - Applications called NetBIOS functions (e.g., `NetBIos()` API in Windows).
        
    - These calls were transported via NetBIOS Session Service on TCP/139.
        
- **How it works**:
    
    - First, **name resolution** (via NBT-NS on UDP/137) finds the target host’s IP.
        
    - Then, TCP/139 establishes a **NetBIOS session**:
        
        - `Session Request` (who am I talking to?)
            
        - `Positive Session Response` (ok, let’s talk)
            
    - After session setup, SMB traffic flows inside this NetBIOS channel.
        
- **Today**:
    
    - Still present for backward compatibility (Win9x, NT, mixed networks).
        
    - Disabled in modern hardened networks (SMB Direct on TCP/445 preferred).
        
- **Example Wireshark view**:
    
    - Frame: `Session Request, to <20> from <00>` (NetBIOS name suffixes mark service type).
        
    - Followed by: `SMB: Negotiate Protocol Request` inside the NetBIOS session.
        

---

## 2. SMB over TCP (**445/tcp**)

- **Modern standard**: Since Windows 2000, SMB can bypass NetBIOS entirely and bind directly to TCP/445.
    
- **Why 445 matters**:
    
    - Eliminates dependency on NetBIOS/UDP 137 or TCP 139.
        
    - Direct, faster transport for SMB traffic.
        
- **What runs here**:
    
    - **SMBv1** (deprecated, vulnerable to EternalBlue).
        
    - **SMBv2/v3** (current; supports encryption, signing, multichannel, compression).
        
- **Usage**:
    
    - File and printer sharing (`\\HOST\share`).
        
    - Authentication (NTLM/Kerberos exchanges inside SMB session setup).
        
    - Named Pipes (`\\HOST\IPC$` → used by MSRPC).
        
- **Packet example**:
    
    - Client → Server: `Negotiate Protocol Request` (SMB dialects: 3.1.1, 3.0.2, etc.)
        
    - Server → Client: `Negotiate Protocol Response` (chooses best dialect).
        
    - Followed by `Session Setup AndX` (NTLM/Kerberos auth), then `Tree Connect AndX` (`IPC$`, `C$`, `Admin$`, or user share).
        

---

## 3. Named Pipes via IPC$ Share

- **Concept**: A **pipe** is an IPC channel that looks like a file (`\\.\pipe\mypipe`).
    
    - On a **local system**: processes use `\\.\pipe\…` for communication.
        
    - Over the network: SMB exposes them through the **IPC$ special share**.
        
- **Path example**:
    
    - Local: `\\.\pipe\samr`
        
    - Remote: `\\HOST\IPC$\pipe\samr`
        
- **What flows through**:
    
    - **MSRPC interfaces** (SAMR, LSA, Netlogon, Spooler).
        
    - Example: `\pipe\lsarpc` is used to query security policies.
        
    - Example: `\pipe\samr` lets clients query or modify domain users/groups.
        
- **Mechanics**:
    
    1. Client connects to `\\HOST\IPC$`.
        
    2. Opens `\pipe\…` object (like a file).
        
    3. Server process (e.g., `lsass.exe`) is listening on that pipe.
        
    4. SMB acts as the transport wrapper.
        
- **Security**:
    
    - Access to a pipe is controlled by **ACLs on the named pipe object**.
        
    - SMB authentication (NTLM/Kerberos) must succeed first.
        
- **Packet example** (Wireshark):
    
    - `SMB Create Request: \pipe\samr`
        
    - `MSRPC Bind: uuid=SAMR interface`
        
    - RPC queries/responses (user/group enumeration, etc.).