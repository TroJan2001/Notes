This module explores common locations and methods for storing passwords. Understanding where passwords are typically kept can help improve security practices and identify potential vulnerabilities.
# Unattended Windows Installations

When we use "unattended windows installation" to install windows on a large scale (many hosts), such installations require the use of an administrator account to perform the initial setup, which might end up being stored in the machine in the following locations:

```
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

We might encounter a useful information such as credentials, for example:

```
<Credentials>
    <Username>Administrator</Username>
    <Domain>thm.local</Domain>
    <Password>MyPassword123</Password>
</Credentials>
```
# Powershell History

We can check Powershell history using the following command:

```shell-session
%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
# Saved Windows Credentials

Windows enables us to use and store other users' credentials on the system. To list these saved credentials, we can use the following command:

```shell-session
cmdkey /list
```

Although we can't see the actual passwords, we can still utilize these credentials. If we find any credentials worth using, we can execute commands as that user with the `runas` command and the `/savecred` option:

```shell-session
runas /savecred /user:<username> cmd.exe
```
# IIS Configuration (web.config)

The `web.config` file can store database passwords and authentication mechanisms. Depending on your IIS version, you can find it at:

```
C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
```

To quickly find database connection strings in the file, use:

```shell-session
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

# Retrieve Credentials from PuTTY

PuTTY is a commonly used SSH client on Windows that allows users to store session configurations, including IP addresses and usernames. While it doesn't save SSH passwords, it does store proxy configurations with cleartext authentication credentials.

To retrieve stored proxy credentials, search the registry for `ProxyPassword` using the following command:

```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

**Note:** "Simon Tatham" refers to the creator of PuTTY, not the username.
Similarly, other software that stores passwords—such as browsers, email clients, FTP clients, and VNC software—also has methods for recovering saved passwords.