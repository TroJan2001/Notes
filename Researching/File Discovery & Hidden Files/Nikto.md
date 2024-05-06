Nikto is capable of performing an assessment on all types of webservers (and isn't application-specific such as WPScan.). Nikto can be used to discover possible vulnerabilities including:

- Sensitive files
- Outdated servers and programs (i.e. [vulnerable web server installs](https://httpd.apache.org/security/vulnerabilities_24.html))
- Common server and software misconfigurations (Directory indexing, cgi scripts, x-ss protections)
# Useful Commands:

To make a basic scan we can use:

```bash
nikto -h <ip address>
#or use this for a webpage that requires login
nikto -h <ip address> -id "user:pass"
```

To look for hosts across an entire network range:

```bash
nmap -p <port> <ip address> -oG - | nikto -h -
```

We can use the `--list-plugins` flag with Nikto to list the plugins.

|Plugin Name|Description|
|---|---|
|apacheusers|Attempt to enumerate Apache HTTP Authentication Users|
|cgi|Look for CGI scripts that we may be able to exploit|
|robots|Analyse the robots.txt file which dictates what files/folders we are able to navigate to|
|dir_traversal|Attempt to use a directory traversal attack (i.e. LFI) to look for system files such as /etc/passwd on Linux (http://ip_address/application.php?view=../../../../../../../etc/passwd)|

To use a plugin we can simply use the `-Plugin` flag and then the Plugin Name, like so:

```bash
nikto -h <ip address> -Plugin apacheuser
```

We can increase the verbosity of our Nikto scan by providing the following arguments with the`-Display` flag.

|Argument|Description|Reasons for Use|
|---|---|---|
|1|Show any redirects that are given by the web server.|Web servers may want to relocate us to a specific file or directory, so we will need to adjust our scan accordingly for this.|
|2|Show any cookies received|Applications often use cookies as a means of storing data. For example, web servers use sessions, where e-commerce sites may store products in your basket as these cookies. Credentials can also be stored in cookies.|
|E|Output any errors|This will be useful for debugging if your scan is not returning the results that you expect!|

We can use the `-Tuning` flag and set one of the following Vulnerability scans:

|Category Name|Description|Tuning Option|
|---|---|---|
|File Upload|Search for anything on the web server that may permit us to upload a file. This could be used to upload a reverse shell for an application to execute.|0|
|Misconfigurations / Default Files|Search for common files that are sensitive (and shouldn't be accessible such as configuration files) on the web server.|2|
|Information Disclosure|Gather information about the web server or application (i.e. verison numbers, HTTP headers, or any information that may be useful to leverage in our attack later)|3|
|Injection|Search for possible locations in which we can perform some kind of injection attack such as XSS or HTML|4|
|Command Execution|Search for anything that permits us to execute OS commands (such as to spawn a shell)|8|
|SQL Injection|Look for applications that have URL parameters that are vulnerable to SQL Injection|9|

We can use the `-o` argument (short for `-Output`) and provide both a filename and compatible extension. We _can_ specify the format (`-f`) specifically, but Nikto is smart enough to use the extension we provide in the`-o` argument to adjust the output accordingly, like so:

```bash
nikto -h http://ip_address -o report.html
```