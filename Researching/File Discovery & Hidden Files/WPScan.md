
The WPScan framework is capable of enumerating & researching a few security vulnerability categories present in WordPress sites - including - but not limited to:

- Sensitive Information Disclosure (Plugin & Theme installation versions for disclosed vulnerabilities or CVE's)
- Path Discovery (Looking for misconfigured file permissions i.e. wp-config.php)
- Weak Password Policies (Password bruteforcing)
- Presence of Default Installation (Looking for default files)
- Testing Web Application Firewalls (Common WAF plugins)

# Useful Commands:

To Enumerate for installed themes we can use:

```bash
wpscan --url http://<hostname> --enumerate t
```

Likewise we can use these tags to enumerate on different categories:

|Flag|Description|Full Example|
|---|---|---|
|p|Enumerate Plugins|--enumerate p|
|t|Enumerate Themes|--enumerate t|
|u|Enumerate Usernames|--enumerate -u|
|v|Use WPVulnDB to cross-reference for vulnerabilities. Example command looks for vulnerable plugins (p)|--enumerate vp|
|aggressive|This is an aggressiveness profile for WPScan to use.|--plugins-detection aggressive|
|passive|This is an aggressiveness profile for WPScan to use.|--plugins-detection passive|

 To perform a password attack we can use:

```bash
wpscan –-url http://<hostname> –-passwords <wordlist> –-usernames <username>
```

