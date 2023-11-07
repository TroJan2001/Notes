This process which is also known as Session Manager Subsystem is responsible for creating new sessions. and it is a ==user-mode Process==.

Also it starts ==csrss.exe== and ==wininit.exe== in session 0, ==csrss.exe== and ==winlogon.exe== for Session 1.

Any other subsystem listed in the `Required` value of `HKLM\System\CurrentControlSet\Control\Session Manager\Subsystems` is also launched.

![](../../Attachments/Pasted%20image%2020231105010116.png)

SMSS is also responsible for creating environment variables, virtual memory paging files and starts ==winlogon.exe== (the Windows Logon Manager).

### Normal State :

![](../../Attachments/Pasted%20image%2020231105010122.png)

**Image Path**:  %SystemRoot%\System32\smss.exe
**Parent Process**:  System
**Number of Instances**:  One master instance and child instance per session. The child instance exits after creating the session.
**User Account**:  Local System
**Start Time**:  Within seconds of boot time for the master instance

### What is unusual?

- A different parent process other than System (4)
- The image path is different from C:\Windows\System32
- More than one running process. (children self-terminate and exit after each new session)
- The running User is not the SYSTEM user
- Unexpected registry entries for Subsystem