1. Remote Execution & Lateral Movement
   ├─ PsExec / Impacket-psexec
   ├─ SMBExec / Impacket-smbexec
   ├─ WMIExec / Impacket-wmiexec
   ├─ winexe
   ├─ Scheduled Task / at (DCOMExec, atexec)
   └─ WinRM / evil-winrm / PowerShell Remoting

2. Enumeration & Reconnaissance
   ├─ rpcclient (Samba)
   ├─ smbclient / smbmap
   ├─ enum4linux / enum4linux-ng
   └─ BloodHound / PlumHound

3. Credential Extraction & Abuse
   ├─ mimikatz
   ├─ secretsdump.py (Impacket)
   ├─ Rubeus / Kerbrute
   ├─ Kerberoasting / AS-REP Roasting
   └─ Pass-the-Hash (via PsExec, WMIExec, CrackMapExec, Metasploit)

4. Post-Exploitation Frameworks & Agents
   ├─ Empire
   ├─ Metasploit Framework
   ├─ GhostPack (e.g., Rubeus, Seatbelt, SharpUp)
   └─ Custom C2 Agents (PowerShell / C#)

5. Attack Delegation & Ticketing
   ├─ Golden Ticket abuse
   ├─ Unconstrained Delegation & PetitPotam
   ├─ Kerberos Ticket Theft & Abuse

6. Visibility, Detection & Defensive Overviews
   ├─ Logging artifacts (Service creation, Windows Event 5145)
   ├─ Threat hunting patterns for PsExec & clones
   └─ Behavioral detection via named pipes, telemetry, stealth lateral movement

7. Active Directory Privilege Escalation (Famous "Potatoes" & Others)
   ├─ JuicyPotato / RoguePotato / PrintSpoofer → exploit SeImpersonatePrivilege
   ├─ RottenPotato / SweetPotato → NTLM relay → SYSTEM
   ├─ PrintNightmare (CVE-2021-34527) → Print Spooler exploitation
   ├─ ZeroLogon (CVE-2020-1472) → Domain Controller takeover
   ├─ DCSync / DCShadow → abuse replication rights
   ├─ NoPac (SamAccountName spoofing + Kerberos relay)
   ├─ Kerberos Unconstrained/Constrained Delegation abuse
   ├─ ACL abuse (GenericAll, WriteDACL, AddMember rights in AD)
   ├─ ADCS / Certificate Templates exploitation (ESC1-ESC8 paths)
   └─ NTLM relay family (PetitPotam + PrinterBug + DFSCoerce)
