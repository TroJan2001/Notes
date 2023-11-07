#### ==**Find directories & hidden website pages**==

Gobuster is a tool used to brute-force: URIs (directories and files) in web sites, DNS subdomains (with wildcard support), Virtual Host names on target web servers, Open Amazon S3 buckets, Open Google Cloud buckets and TFTP servers.

# Using "dir" Mode

To use "dir" mode, you start by typing `gobuster dir`. After that, you will need to add the URL and wordlist using the `-u` and `-w` options -here is an example of a good dir wordlist in the following command-, respectively. Like so:

```bash
gobuster dir -u http://MACHINE-IP or http://hostname -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -x .txt,.php 
```



## Basic Flags:

|**Flag** | **Long Flag** | **Description** |
| :-------:| :------:| :------:| 
|-t|--threads|Number of concurrent threads (default 10)|
|-v|--verbose|Verbose output|
|-z|--no-progress|Don't display progressl|
|-q|--quiet|Don't print the banner and other noise|
|-o|--output|Output file to write results to|

## More Flags:

|**Flag** | **Long Flag** | **Description** |
| :-------:| :------:| :------:| 
|-c|--cookies|Cookies to use for requests|
|-x|--extensions|File extension(s) to search for|
|-H|--headers|Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2'|
|-k|--no-tls-validation|Skip TLS certificate verification|
|-n|--no-status|Don't print status codes|
|-P|--password|Password for Basic Auth|
|-s|--status-codes|Positive status codes|
|-b|--status-codes-blacklist|Negative status codes|
|-U|--username|Username for Basic Auth|

# Using "dns" Mode

To use "dns" mode, we start by typing `gobuster dns`. After that, we will need to add the domain and wordlist using the -d and -w options, respectively. Like so:

```bash
gobuster dns -d mydomain.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

## More Flags for DNS Mode:

|Flag|Long Flag|Description|
|---|---|---|
|-c|--show-cname|Show CNAME Records (cannot be used with '-i' option)|
|-i|--show-ips|Show IP Addresses|
|-r|--resolver|Use custom DNS server (format server.com or server.com:port)|

# vhost Mode

The last and final mode we'll focus on is the "vhost" mode. This allows Gobuster to brute-force virtual hosts. Virtual hosts are different websites on the same machine. In some instances, they can appear to look like sub-domains, but don't be deceived! Virtual Hosts are IP based and are running on the same server.

## Using vhost Mode

To use "vhost" mode, you start by typing `gobuster vhost`. After that, you will need to add the domain and wordlist using the `-u` and `-w` options, respectively. Like so:

```bash
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

This will tell Gobuster to do a virtual host scan [http://example.com](http://example.com/) using the selected wordlist.

**Important Note:** After much researching the vhost command won't work unless we add this tag `--append-domain` .
## Other Useful Flags for vhost Mode:

A lot of the same flags that are useful for "dir" mode actually still apply to virtual host mode. Please check out the "dir" mode section for these and take a look at the [official documentation](https://github.com/OJ/gobuster#vhost-mode-options) for the full list. There's really too many that are similar to put them back here.