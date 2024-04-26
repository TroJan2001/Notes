LFI attacks against web applications are often due to a developers' lack of security awareness. With PHP, using functions such as include, require, include_once, and require_once often contribute to vulnerable web applications

even not all payloads may work, but take a look here on a very useful set of payloads that may vary depending on the situation you are dealing with:
https://medium.com/@nyomanpradipta120/local-file-inclusion-vulnerability-cfd9e62d12cb

Below are some common OS files you could use when testing.

| **Location**                | **Description**                                                                                                                                                   |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| /etc/issue                  | contains a message or system identification to be printed before the login prompt.                                                                                |
| /etc/profile                | controls system-wide default variables, such as Export variables, File creation mask (umask), Terminal types, Mail messages to indicate when new mail has arrived |
| /proc/version               | specifies the version of the Linux kernel                                                                                                                         |
| /etc/passwd                 | has all registered user that has access to a system                                                                                                               |
| /etc/shadow                 | contains information about the system's users' passwords                                                                                                          |
| /root/.bash_history         | contains the history commands for root user                                                                                                                       |
| /var/log/dmessage           | contains global system messages, including the messages that are logged during system startup                                                                     |
| /var/mail/root              | all emails for root user                                                                                                                                          |
| /root/.ssh/id_rsa           | Private SSH keys for a root or any known valid user on the server                                                                                                 |
| /var/log/apache2/access.log | the accessed requests for Apache  webserver                                                                                                                       |
| C:\boot.ini                 | contains the boot options for computers with BIOS firmware                                                                                                        |

**Note:**  `curl -X POST https://test.com -d 'method=GET&file=/etc/flag1'` this command is manipulating POST to ask the server to make a get request, since in the example we couldn't try 'GET' method directly

Many tricks have been published over the years:

- `PHP_SESSION_UPLOAD_PROGRESS` trick - [https://blog.orange.tw/2018/10/](https://blog.orange.tw/2018/10/)
- Use wrappers like `compress.zlib://` to upload a temporary file - [https://balsn.tw/ctf_writeup/20191228-hxp36c3ctf/#includer](https://balsn.tw/ctf_writeup/20191228-hxp36c3ctf/#includer)
- Temp files / `FindFirstFile` tricks [https://gynvael.coldwind.pl/?id=376](https://gynvael.coldwind.pl/?id=376)
- LFI with `phpinfo()` assistance - [https://insomniasec.com/cdn-assets/LFI_With_PHPInfo_Assistance.pdf](https://insomniasec.com/cdn-assets/LFI_With_PHPInfo_Assistance.pdf)
- Obsolete `/proc/self/environ` tricks - [https://www.exploit-db.com/papers/12886](https://www.exploit-db.com/papers/12886)
- Obsolete `/var/log/apache2/*log` (has this ever worked)?
- etc.

RFI

Remote File Inclusion (RFI) is a technique to include remote files and into a vulnerable application. Like LFI, the RFI occurs when improperly sanitizing user input, allowing an attacker to inject an external URL into include function. One requirement for RFI is that the allow_url_fopen option needs to be on.
  
The risk of RFI is higher than LFI since RFI vulnerabilities allow an attacker to gain Remote Command Execution (RCE) on the server. Other consequences of a successful RFI attack include:

- Sensitive Information Disclosure
- Cross-site Scripting (XSS)
- Denial of Service (DoS)

An external server must communicate with the application server for a successful RFI attack where the attacker hosts malicious files on their server. Then the malicious file is injected into the include function via HTTP requests, and the content of the malicious file executes on the vulnerable application server.

![](Attachments/Pasted%20image%2020231105010437.png)