The **Windows Logon**, **winlogon.exe**, is responsible for handling the **Secure Attention Sequence** (SAS). It is the ALT+CTRL+DELETE key combination users press to enter their username & password.

This process is also responsible for loading the user profile. It loads the user's NTUSER.DAT into HKCU, and userinit.exe loads the user's shell. Read more about this process [here](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc939862(v=technet.10)?redirectedfrom=MSDN).

![](../../Attachments/Pasted%20image%2020231105010245.png)

==smss.exe launches this process along with a copy of csrss.exe within Session 1.==
### Normal State:

![](../../Attachments/Pasted%20image%2020231105010252.png)

**Image Path**:  %SystemRoot%\System32\winlogon.exe
**Parent Process**:  Created by an instance of smss.exe that exits, so analysis tools usually do not provide the parent process name.
**Number of Instances**:  One or more
**User Account**:  Local System
**Start Time**:  Within seconds of boot time for the first instance (for Session 1). Additional instances occur as new sessions are created, typically through Remote Desktop or Fast User Switching logons.

  
### What is unusual?

- An actual parent process. (smss.exe calls this process and self-terminates)
- Image file path other than C:\Windows\System32
- Subtle misspellings to hide rogue processes in plain sight
- Not running as SYSTEM
- Shell value in the registry other than explorer.exe