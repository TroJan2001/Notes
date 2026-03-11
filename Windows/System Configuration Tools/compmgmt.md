We're continuing with Tools that are available through the System Configuration panel.  

The **Computer Management** (==`compmgmt`==) utility has three primary sections: System Tools, Storage, and Services and Applications.

![](../../Attachments/Pasted%20image%2020231105010307.png)


System Tools, Starting with== ==Task Scheduler== which we can create and manage that could be carried out automatically on specific periods.

Next is ==**Event Viewer**==, which allows us to view the events that occurred on computer, and we can use it to diagnose problems.

![](../../Attachments/Pasted%20image%2020231105010315.png)

**Event Viewer has three panes:**

1. The pane on the left provides a hierarchical tree listing of the event log providers. (as shown in the image above)
2. The pane in the middle will display a general overview and summary of the events specific to a selected provider.
3. The pane on the right is the actions pane.

**There are five types of events that can be logged. Below is a table from [docs.microsoft.com](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-types) providing a brief description for each.**

![](../../Attachments/Pasted%20image%2020231105010323.png)

The standard logs are visible under Windows Logs. Below is a table from [docs.microsoft.com](https://docs.microsoft.com/en-us/windows/win32/eventlog/eventlog-key) providing a brief description for each.

![](../../Attachments/Pasted%20image%2020231105010332.png)

For more information about Event Viewer and Event Logs, please refer to the Windows Event Log [room](https://tryhackme.com/room/windowseventlogs).

==**Shared Folders**== is where we can see the shared folders that others can connect to.

==shares==,``` are the default share of Windows, C$, and default remote administration shares created by Windows, such as ADMIN$.```

As with any object in Windows, you can right-click on a folder to view its properties, such as Permissions (who can access the shared resource). 

Under ==**Sessions**==, you will see a list of users who are currently connected to the shares. In this VM, you won't see anybody connected to the shares.

All the folders and/or files that the connected users access will list under ==**Open Files**==.

In ==**Performance*==*, you'll see a utility called **Performance Monitor**
(==`perfmon`==), which we we can view some data about the performance of the PC.

==**Device Manager**== allows us to view and configure the hardware, such as disabling any hardware attached to the computer.
 
==**Disk Management**==, which could be located under ==Storage==, is a system utility in Windows that enables you to perform advanced storage tasks such as:
- Set up a new drive
- Extend a partition
- Shrink a partition
- Assign or change a drive letter (ex. E:)

==**Services and Applications**==, a service is a special type of application that runs in the background. Here you can do more than enable and disable a service, such as view the Properties for the service.

v

==WMI== Control configures and controls the **Windows Management Instrumentation** (WMI) service.

Per Wikipedia, "_WMI allows scripting languages (such as VBScript or Windows PowerShell) to manage Microsoft Windows personal computers and servers, both locally and remotely. Microsoft also provides a command-line interface to WMI called Windows Management Instrumentation Command-line (WMIC)._"

**Note**: The WMIC tool is deprecated in Windows 10, version 21H1. Windows PowerShell supersedes this tool for WMI.

