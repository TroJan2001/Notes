Log Poisoning involves reading a log file through a “file inclusion” (LFI) and modifying the text of the headers (e.g., User-agent) to write arbitrary code and achieve its execution (RCE) on the victim machine.

**Perquisites: LFI**
We send a malicious code inside the `User-Agent` header for example, then we access the log file that contains this php code.

path examples for Logs: 

```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/vsftpd.log
/var/log/auth.log
/var/log/mail.log
```
