
John can be very particular about the formats it needs data in to be able to work with it, for this reason- in order to crack /etc/shadow passwords, you must combine it with the /etc/passwd file in order for John to understand the data it's being given. To do this, we use a tool built into the John suite of tools called unshadow. The basic syntax of unshadow is as follows:

```bash
unshadow [path to passwd] [path to shadow]
```

**Note on the files**

When using unshadow, you can either use the entire /etc/passwd and /etc/shadow file- if you have them available, or you can use the relevant line from each, for example:

**FILE 1 - local_passwd **

Contains the /etc/passwd line for the root user:

`root:x:0:0::/root:/bin/bash`

**FILE 2 - local_shadow**

Contains the /etc/shadow line for the root user:  
`root:$6$2nwjN454g.dv4HN/$m9Z/r2xVfweYVkrr.v5Ft8Ws3/YYksfNwq96UL1FX0OJjY1L6l.DS3KEVsZ9rOVLB/ldTeEL/OIhJZ4GMFMGA0:18576::::::`

and suppose the output file in unshadowed.txt

Now we crack the unshadowed version

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt
```

Note that format type is optional.