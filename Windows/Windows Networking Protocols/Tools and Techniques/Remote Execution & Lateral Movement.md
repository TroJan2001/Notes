All of the following remote execution techniques **require administrative credentials** on the target host.

- This can be either a **local Administrator** account or a **domain account** that is a member of the target’s **Administrators group**.
    
- Without admin rights, service creation, WMI process creation, scheduled tasks, or WinRM session setup will fail.
## PsExec / Impacket-psexec

**Flow:**

1. Authenticate to target via **SMB (445)** with admin creds or hash.
    
2. Upload service binary (`PsExecSvc.exe`) to **ADMIN$ share**.
    
3. Use **RPC → Service Control Manager (svcctl)** to create/start the service.
    
4. Service launches and opens a **named pipe** (`\pipe\psexesvc`).
    
5. Attacker sends commands and receives output via named pipe.
    
6. Cleanup: remove service and files.
    
- Requires an account with **local administrator privileges** on the target host.
    
    - This can be either:
        
        - A **local admin account**, or
            
        - A **domain account** that is part of the target’s **Administrators group**.
            
- PsExec needs rights to:
    
    - Write to `ADMIN$`
        
    - Create and start services (i.e., **SC_MANAGER_CREATE_SERVICE**, **SERVICE_START**)  
- Without such permissions, PsExec will fail to operate.
**Transport Stack:**  
`SMB (445) → RPC (svcctl) → Named Pipes`

---

## SMBExec / Impacket-smbexec

**Flow:**

1. **Authenticate to target via SMB (445)**
    
    - Requires **local administrator privileges** (same as PsExec).
        
    - Can be a **local admin** account or a **domain account** in the target’s Administrators group.
        
    - Why admin? Because SMBExec still needs rights to create and control services remotely.
        
2. **Service creation via RPC → SCM**
    
    - Connects to the **Service Control Manager (svcctl RPC interface)** over SMB.
        
    - Creates a temporary service.
        
    - Instead of pointing the service to a helper binary (like PsExec), it points it to a **command line that runs `cmd.exe` with redirection**.
        
    
    Example (simplified):
    
    `cmd.exe /Q /c whoami > \\127.0.0.1\ADMIN$\__output.txt 2>&1`
    
3. **Command execution**
    
    - SCM starts the service.
        
    - The service runs the above command.
        
    - `cmd.exe` executes the payload.
        
    - Output (stdout + stderr) is redirected into a temporary file stored in the ADMIN$ share.
        
4. **Output retrieval via SMB**
    
    - The attacker’s client connects back to `\\Target\ADMIN$\__output.txt` over SMB.
        
    - Reads the file contents (e.g., `nt authority\system`).
        
    - Deletes the file afterwards.
        
5. **Cleanup**
    
    - Service is stopped and removed.
        
    - Temporary output file is deleted from ADMIN$.
---

## WMIExec / Impacket-wmiexec

**Flow:**

1. **Authenticate**
    
    - Needs **admin creds** (local or domain admin).
        
    - SMB is used for authentication and later to read output files.
        
2. **Connect to WMI**
    
    - Uses **DCOM/RPC (135 + dynamic ports)** to reach the WMI service (`WMIPrvSE.exe`) on the target.
        
    - This gives remote access to Windows Management Instrumentation (system management API).
        
3. **Run command**
    
    - Calls the WMI class `Win32_Process.Create`.
        
    - That makes the target machine launch a new process (e.g. `cmd.exe /c whoami`).
        
4. **Redirect output**
    
    - The command’s stdout/stderr is redirected into a temporary file in the `ADMIN$` share.
        
    - Example: `C:\Windows\Temp\__1234.output`.
        
5. **Retrieve output**
    
    - Attacker’s tool goes back over **SMB** to read the file.
        
    - Deletes the temporary file afterward.
        
**Transport Stack:** `SMB (445) → DCOM/RPC (135) → WMI → SMB (output file)`

---

## winexe

**winexe behaves like PsExec but is tailored for Linux users**, functioning similarly to Impacket’s psexec.

**Flow:**

1. **Authenticate**
    
    - Run from Linux against a Windows target.
        
    - Requires **admin creds** (local or domain) because it needs to create/manage services remotely.
        
2. **Service creation**
    
    - Connects to the **Service Control Manager (SCM)** over **RPC (svcctl)**.
        
    - Creates a temporary service that points to `cmd.exe /c <command>`.
        
3. **Execution**
    
    - SCM starts the service, which runs the attacker’s command under **SYSTEM**.
        
4. **Output**
    
    - Depending on version:
        
        - Some builds use **named pipes** (like PsExec).
            
        - Others redirect to a temporary file (like SMBExec).
            
    - Either way, output is fetched back over **SMB**.
        
5. **Cleanup**
    
    - Service removed once done.
        
    - Temporary files (if used) deleted.
        

---

**Transport Stack:**  
`SMB (445) → RPC (svcctl) → [Pipe/File for output]`

---

## Scheduled Task / atexec / DCOMExec

**Flow:**

1. **Authenticate**
    
    - Needs **admin creds** (local or domain).
        
    - Connects via **RPC/DCOM (135 + dynamic ports)** to the Task Scheduler service (`Schedule` service).
        
2. **Create scheduled task**
    
    - Defines a temporary task with the attacker’s command, e.g.:
        
        `cmd.exe /c whoami > C:\Windows\Temp\out.txt 2>&1`
        
3. **Run the task**
    
    - Task Scheduler service starts the process as SYSTEM (because attacker is admin).
        
4. **Output**
    
    - Command output is redirected into a temporary file under `ADMIN$`.
        
    - Attacker retrieves that file over SMB.
        
5. **Cleanup**
    
    - Temporary task is deleted.
        
    - Output file is removed.
        

**Transport Stack:**  
`MSRPC (135 + Task Scheduler interface) → SMB (445, ADMIN$ for output)`

---

## WinRM / evil-winrm / PowerShell Remoting

**Flow:**

1. **Connect**
    
    - Attacker connects to **WinRM service**:
        
        - Port **5985/tcp** (HTTP)
            
        - Port **5986/tcp** (HTTPS, encrypted)
            
2. **Authenticate**
    
    - Can use:
        
        - **Kerberos** (with domain creds/tickets)
            
        - **NTLM** (with password or hash)
            
        - Or a **certificate** (if configured).
            
3. **Execute commands**
    
    - Uses **WS-Management (WS-Man)** protocol, which wraps commands in **SOAP XML messages**.
        
    - Can run a single command or start an interactive **PowerShell Remoting** session.
        
4. **Output**
    
    - Responses are packaged back in SOAP messages and sent over the same HTTP(S) channel.
        
5. **Session**
    
    - Feels very much like a native PowerShell session — attacker can upload scripts, run modules, etc.
        

**Transport Stack:**  
`HTTP(S) → WinRM (WS-Man SOAP) → PowerShell Remoting`