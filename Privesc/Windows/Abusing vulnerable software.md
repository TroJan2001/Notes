
Software installed on the target system can present various privilege escalation opportunities. As with drivers, organisations and users may not update them as often as they update the operating system. You can use the `wmic` tool to list software installed on the target system and its versions.

 The command below will dump information it can gather on installed software:


```
wmic product get name,version,vendor
```

Keep in mind that the `wmic product` command may not list all installed programs. Some applications might not appear, depending on how they were installed. It's always a good idea to check for desktop shortcuts, available services, or any other signs that could indicate the presence of additional software that may be vulnerable.

After collecting product version information, we can search for known exploits related to the installed software on websites such as Exploit-DB, Packet Storm, or even through a simple Google search, among many other resources.