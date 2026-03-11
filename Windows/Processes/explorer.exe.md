**Windows Explorer**, **explorer.exe**. This process gives the user access to their folders and files. It also provides functionality for other features, such as the Start Menu and Taskbar.

As mentioned previously, the ==Winlogon== process runs userinit.exe, which launches the value in ==`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`.== ==Userinit.exe== exits after spawning ==explorer.exe==. Because of this, the parent process is non-existent.

There will be many child processes for explorer.exe.

![](../../Attachments/Pasted%20image%2020231105010007.png)
### Normal State:

![](../../Attachments/Pasted%20image%2020231105010014.png)

**Image Path**:  %SystemRoot%\explorer.exe
**Parent Process**:  Created by userinit.exe and exits
**Number of Instances**:  One or more per interactively logged-in user
**User Account**:  Logged-in user(s)
**Start Tim**e:  First instance when the first interactive user logon session begins
### What is unusual?

- An actual parent process. (userinit.exe calls this process and exits)
- Image file path other than C:\Windows
- Running as an unknown user
- Subtle misspellings to hide rogue processes in plain sight
- Outbound TCP/IP connections