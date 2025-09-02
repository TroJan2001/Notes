# 🔹 1. Remote Execution & Lateral Movement

| Tool                                   | Flow                                                                                                                                             | Protocol/Transport                                              |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------- |
| **PsExec / Impacket-psexec**           | Authenticates via SMB → creates a Windows Service (`PSEXESVC`) remotely → service runs attacker command → output piped back over SMB named pipe. | **SMB (445/tcp)** + Named Pipes (IPC$)                          |
| **SMBExec / Impacket-smbexec**         | Same SMB path, but instead of creating a service, it uses a semi-interactive shell via SMB pipes.                                                | **SMB (445/tcp)**                                               |
| **WMIExec / Impacket-wmiexec**         | Connects via DCOM/RPC → issues WMI `Win32_Process.Create` call → process runs remotely → output redirected through SMB backchannel.              | **DCOM over MSRPC (135/tcp + dynamic RPC)** with SMB for output |
| **winexe**                             | Linux client for SMB service execution (similar to PsExec).                                                                                      | **SMB (445/tcp)**                                               |
| **Scheduled Task / atexec / DCOMExec** | Connects via RPC/DCOM → schedules a task (Task Scheduler service) on target → task runs attacker command.                                        | **MSRPC (135/tcp + dynamic)**                                   |
| **WinRM / evil-winrm / PS Remoting**   | Uses WS-Management protocol (SOAP over HTTP/S) → remote PowerShell execution.                                                                    | **WinRM (5985/tcp HTTP, 5986/tcp HTTPS)**                       |

---
# 🔹 2. Enumeration & Reconnaissance

| Tool                           | Flow                                                                                                                  | Protocol/Transport                                 |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| **rpcclient**                  | Talks directly to MSRPC interfaces exposed by SMB/DC (like SAMR, LSARPC, Netlogon) → queries users, groups, policies. | **MSRPC over SMB (445/tcp)**                       |
| **smbclient / smbmap**         | Enumerates file shares, permissions, contents.                                                                        | **SMB (445/tcp)**                                  |
| **enum4linux / enum4linux-ng** | Wrapper around rpcclient, smbclient, LDAP queries → dumps domain info.                                                | **SMB + RPC + LDAP (389/tcp)**                     |
| **BloodHound / PlumHound**     | Collects LDAP queries (users, groups, ACLs) + SMB sessions + GPOs → graph analysis.                                   | **LDAP (389/tcp), SMB (445/tcp), MSRPC (135/tcp)** |

---
# 🔹 3. Credential Extraction & Abuse

|Tool|Flow|Protocol/Transport|
|---|---|---|
|**mimikatz**|Local only → extracts from LSASS, SAM, tickets in memory.|**Local (no network)**|
|**secretsdump.py (Impacket)**|Uses DRSUAPI (MSRPC replication service) or SMB/SAMR to dump password hashes remotely.|**MSRPC over SMB (445/tcp)**|
|**Rubeus**|Kerberos ticket request/renew/inject → abuses KDC flows.|**Kerberos (88/tcp & udp)**|
|**Kerbrute**|Brute-force user/password via Kerberos pre-auth.|**Kerberos (88/tcp & udp)**|
|**Kerberoasting / AS-REP Roasting**|Asks KDC for TGS (Kerberoast) or AS-REP (no preauth) → crack offline.|**Kerberos (88/tcp)**|
|**Pass-the-Hash (PsExec, WMIExec, etc.)**|Reuses NTLM hash in authentication handshake over SMB/DCOM.|**SMB, RPC, WinRM depending on tool**|

---
# 🔹 4. Post-Exploitation Frameworks & Agents

|Tool|Flow|Protocol/Transport|
|---|---|---|
|**Empire**|PowerShell agents beacon back to C2 (HTTP/HTTPS, SMB, etc.).|**Web (80/443/tcp) or SMB pipes**|
|**Metasploit Framework**|Multi-protocol exploitation & post-exploitation (can use SMB, RPC, HTTP, custom).|**Depends on module**|
|**GhostPack (Seatbelt, SharpUp, Rubeus)**|Local recon, Kerberos abuse, privilege checks.|**Mostly Local, some Kerberos (88/tcp)**|
|**Custom C2 Agents**|Beacon back over chosen channel (HTTP, HTTPS, DNS, SMB).|**Flexible**|

---
# 🔹 5. Attack Delegation & Ticketing

|Technique|Flow|Protocol/Transport|
|---|---|---|
|**Golden Ticket**|Forge TGT with krbtgt hash → use in Kerberos flow → valid everywhere.|**Kerberos (88/tcp)**|
|**Silver Ticket**|Forge TGS with service account hash → present directly to service.|**Kerberos (88/tcp)**|
|**Unconstrained Delegation / PetitPotam**|Force machine with delegation to request TGT → attacker steals forwarded ticket.|**MSRPC (EFSRPC, LSARPC) + Kerberos**|
|**Ticket Theft & Abuse**|Export from LSASS → inject into session → single sign-on bypass.|**Kerberos (88/tcp)**|

---
# 🔹 6. Active Directory Privilege Escalation

|Exploit|Flow|Protocol/Transport|
|---|---|---|
|**JuicyPotato / RoguePotato / PrintSpoofer**|Abuse SeImpersonatePrivilege → force system process to authenticate → impersonate SYSTEM.|**Local RPC + NTLM relay (SMB, HTTP)**|
|**RottenPotato / SweetPotato**|Same but relays NTLM locally → SYSTEM.|**Local RPC + SMB/HTTP**|
|**PrintNightmare**|Exploit Print Spooler service via RPC → load malicious DLL.|**MSRPC over SMB (445/tcp), Spooler service**|
|**ZeroLogon**|Abuse Netlogon MSRPC weak crypto → DC takeover.|**Netlogon (MSRPC, 445/tcp)**|
|**DCSync / DCShadow**|Use replication rights → request account hashes or inject objects.|**MSRPC (DRSUAPI) over SMB**|
|**NoPac**|Combine sAMAccountName spoof + Kerberos relay → DA.|**Kerberos + RPC**|
|**Delegation abuse**|Steal or coerce delegated tickets.|**Kerberos**|
|**ACL abuse**|Modify AD ACLs via LDAP → reset passwords, add groups.|**LDAP (389/tcp)**|
|**ADCS / ESC1–ESC8**|Abuse certificate templates → request certs that impersonate accounts.|**ADCS over RPC + HTTP (certsrv)**|
|**NTLM relay family (PetitPotam, PrinterBug, DFSCoerce)**|Coerce machine to auth to attacker, relay NTLM to another service.|**MSRPC (various) + SMB/LDAP/HTTP**|
