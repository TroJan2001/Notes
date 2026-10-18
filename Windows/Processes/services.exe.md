**(wininit.exe > services.exe)**

**Service Control Manager** (SCM) or **services.exe**. Its primary responsibility is to handle system services: loading services, interacting with services and starting or ending services. It maintains a database that can be queried using a Windows built-in utility, ==sc.exe==.

Information regarding services is stored in the registry, ==`HKLM\System\CurrentControlSet\Services`.==

![](../../Attachments/Pasted%20image%2020231105010045.png)

This process also loads device drivers marked as auto-start into memory. 

![](../../Attachments/Pasted%20image%2020231105010056.png)

When a user logs into a machine successfully, this process is responsible for setting the value of the Last Known Good control set (Last Known Good Configuration), ==`HKLM\System\Select\LastKnownGood`==, to that of the CurrentControlSet.

This process is the parent to several other key processes: ==svchost.exe==, ==spoolsv.exe==, ==msmpeng.exe==, and ==dllhost.exe==, to name a few. You can read more about this process [here](https://en.wikipedia.org/wiki/Service_Control_Manager).
### Normal State :

![](../../Attachments/Pasted%20image%2020231105010106.png)

**Image Path**:  %SystemRoot%\System32\services.exe
**Parent Process**:  wininit.exe
**Number of Instances**:  One
**User Account**:  Local System
**Start Time**:  Within seconds of boot time
### What is unusual?

- A parent process other than wininit.exe
- Image file path other than C:\Windows\System32
- Subtle misspellings to hide rogue processes in plain sight
- Multiple running instances
- Not running as SYSTEM