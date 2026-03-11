**(wininit.exe > services.exe > svchost.exe)**

The **Service Host** (Host Process for Windows Services), or **svchost.exe**, is responsible for hosting and managing Windows services.

The services running in this process are implemented as DLLs. The DLL to implement is stored in the registry for the service under the ==`Parameters`== subkey in ==`ServiceDLL`==. The full path is ==`HKLM\SYSTEM\CurrentControlSet\Services\SERVICE NAME\Parameters`==

The example below is the ServiceDLL value for the Dcomlaunch service.

![](../../Attachments/Pasted%20image%2020231105010139.png)

Right-click the service and select Properties. Look at Service DLL.

![](../../Attachments/Pasted%20image%2020231105010148.png)

From the above screenshot, the Binary Path is listed.

Also, notice how it is structured. There is a key identifier in the binary path, and that identifier is ==`-k`== . This is how a legitimate svchost.exe process is called. 

The -k parameter is for grouping similar services to share the same process. This concept was based on the OS design and implemented to reduce resource consumption. Starting from **Windows 10 Version 1703,** services grouped into host processes changed. On machines running more than 3.5 GB of memory, each service will run its own process. You can read more about this process [here](https://en.wikipedia.org/wiki/Svchost.exe). 

Back to the key identifier (-k) from the binary path, in the above screen, the -k value is **Dcomlaunch**. Other services are running with the same binary path in the virtual machine attached to this room.

![](../../Attachments/Pasted%20image%2020231105010157.png)

Each will have a different value for ServiceDLL. Let's take LSM as an example and inspect the value for ServiceDLL.

![](../../Attachments/Pasted%20image%2020231105010205.png)

Since svchost.exe will always have multiple running processes on any Windows system, this process has been a target for malicious use. Adversaries create malware to masquerade as this process and try to hide amongst the legitimate svchost.exe processes. They can name the malware svchost.exe or misspell it slightly, such as scvhost.exe. By doing so, the intention is to go under the radar. Another tactic is to install/call a malicious service (DLL).
### Normal State:

![](../../Attachments/Pasted%20image%2020231105010211.png)

**Image Path**: %SystemRoot%\System32\svchost.exe
**Parent Process**: services.exe
**Number of Instances**: Many
**User Account**: Varies (SYSTEM, Network Service, Local Service) depending on the svchost.exe instance. In Windows 10, some instances run as the logged-in user.
**Start Time**: Typically within seconds of boot time. Other instances of svchost.exe can be started after boot.
### What is unusual?

- A parent process other than services.exe
- Image file path other than C:\Windows\System32
- Subtle misspellings to hide rogue processes in plain sight
- The absence of the -k parameter